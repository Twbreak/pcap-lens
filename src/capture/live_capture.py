import select
import subprocess
import tempfile
from dataclasses import dataclass
from queue import Empty, Queue
from typing import Any

from scapy.all import AsyncSniffer, get_if_list, wrpcap
from scapy.error import Scapy_Exception

from src.domain.models import PacketRecord
from src.parser.pcap_parser import (
    TSHARK_FIELDS,
    is_tshark_available,
    parse_scapy_packet,
    record_from_tshark_row,
)

LIVE_BACKENDS = {"auto", "tshark", "scapy"}


@dataclass(frozen=True)
class LiveBackendStatus:
    preference: str
    backend: str
    tshark_available: bool
    scapy_available: bool


@dataclass(frozen=True)
class CaptureInterface:
    id: str
    label: str


@dataclass
class LiveCaptureSession:
    backend: str
    interface: CaptureInterface
    capture_filter: str
    process: subprocess.Popen | None = None
    sniffer: Any | None = None
    record_queue: Queue[PacketRecord] | None = None
    raw_packet_queue: Queue[Any] | None = None
    failed_queue: Queue[int] | None = None
    pcap_path: str | None = None


def is_scapy_live_available() -> bool:
    return True


def resolve_live_backend(preference: str) -> LiveBackendStatus:
    if preference not in LIVE_BACKENDS:
        raise ValueError(f"Unknown live backend preference: {preference}")

    tshark_available = is_tshark_available()
    scapy_available = is_scapy_live_available()
    backend = "tshark" if preference == "auto" and tshark_available else preference
    if preference == "auto" and not tshark_available:
        backend = "scapy"

    if backend == "tshark" and not tshark_available:
        raise RuntimeError("tshark live capture selected, but tshark is not available on PATH")
    if backend == "scapy" and not scapy_available:
        raise RuntimeError("Scapy live capture is not available")

    return LiveBackendStatus(
        preference=preference,
        backend=backend,
        tshark_available=tshark_available,
        scapy_available=scapy_available,
    )


def list_capture_interfaces(backend_preference: str = "auto") -> list[CaptureInterface]:
    status = resolve_live_backend(backend_preference)
    if status.backend == "tshark":
        return list_tshark_capture_interfaces()
    return list_scapy_capture_interfaces()


def list_tshark_capture_interfaces() -> list[CaptureInterface]:
    """Return tshark capture interfaces from `tshark -D`."""
    if not is_tshark_available():
        return []

    completed = subprocess.run(
        ["tshark", "-D"],
        check=True,
        capture_output=True,
        text=True,
    )
    return parse_tshark_interfaces(completed.stdout)


def list_scapy_capture_interfaces() -> list[CaptureInterface]:
    return [CaptureInterface(id=name, label=name) for name in get_if_list()]


def parse_tshark_interfaces(output: str) -> list[CaptureInterface]:
    interfaces: list[CaptureInterface] = []
    for raw_line in output.splitlines():
        line = raw_line.strip()
        if not line or "." not in line:
            continue

        interface_id, label = line.split(".", 1)
        interface_id = interface_id.strip()
        label = label.strip()
        if interface_id and label:
            interfaces.append(CaptureInterface(id=interface_id, label=label))
    return interfaces


def build_live_tshark_command(
    interface_id: str,
    capture_filter: str = "",
    output_path: str | None = None,
) -> list[str]:
    cmd = ["tshark", "-i", interface_id, "-l", "-n"]
    if capture_filter.strip():
        cmd.extend(["-f", capture_filter.strip()])

    cmd.extend(["-T", "fields", "-E", "separator=/t", "-E", "occurrence=f"])
    for field in TSHARK_FIELDS:
        cmd.extend(["-e", field])
    if output_path:
        cmd.extend(["-w", output_path])
    return cmd


def start_live_capture(
    interface: CaptureInterface,
    capture_filter: str = "",
    backend_preference: str = "auto",
) -> LiveCaptureSession:
    status = resolve_live_backend(backend_preference)
    if status.backend == "tshark":
        return start_tshark_live_capture(interface, capture_filter)
    return start_scapy_live_capture(interface, capture_filter)


def start_tshark_live_capture(
    interface: CaptureInterface,
    capture_filter: str = "",
) -> LiveCaptureSession:
    if not is_tshark_available():
        raise RuntimeError("Live capture requires tshark on PATH")

    pcap_path = _new_temp_pcap_path()
    process = subprocess.Popen(
        build_live_tshark_command(interface.id, capture_filter, output_path=pcap_path),
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=True,
        bufsize=1,
    )
    return LiveCaptureSession(
        backend="tshark",
        process=process,
        interface=interface,
        capture_filter=capture_filter.strip(),
        pcap_path=pcap_path,
    )


def start_scapy_live_capture(
    interface: CaptureInterface,
    capture_filter: str = "",
) -> LiveCaptureSession:
    record_queue: Queue[PacketRecord] = Queue()
    raw_packet_queue: Queue[Any] = Queue()
    failed_queue: Queue[int] = Queue()

    def on_packet(pkt) -> None:
        raw_packet_queue.put(pkt)
        record = parse_scapy_packet(pkt)
        if record is None:
            failed_queue.put(1)
        else:
            record_queue.put(record)

    sniffer = AsyncSniffer(
        iface=interface.id,
        filter=capture_filter.strip() or None,
        prn=on_packet,
        store=False,
    )
    sniffer.start()
    return LiveCaptureSession(
        backend="Scapy",
        sniffer=sniffer,
        record_queue=record_queue,
        raw_packet_queue=raw_packet_queue,
        failed_queue=failed_queue,
        interface=interface,
        capture_filter=capture_filter.strip(),
    )


def stop_live_capture(session: LiveCaptureSession, timeout: float = 2.0) -> None:
    if session.backend == "tshark":
        _stop_tshark_live_capture(session, timeout=timeout)
    else:
        _stop_scapy_live_capture(session)


def _stop_tshark_live_capture(session: LiveCaptureSession, timeout: float = 2.0) -> None:
    process = session.process
    if process is None or process.poll() is not None:
        return

    process.terminate()
    try:
        process.wait(timeout=timeout)
    except subprocess.TimeoutExpired:
        process.kill()
        process.wait(timeout=timeout)


def _stop_scapy_live_capture(session: LiveCaptureSession) -> None:
    if session.sniffer is None:
        return
    try:
        session.sniffer.stop()
    except Scapy_Exception:
        return


def is_capture_running(session: LiveCaptureSession | None) -> bool:
    if session is None:
        return False
    if session.backend == "tshark":
        return session.process is not None and session.process.poll() is None
    return bool(session.sniffer is not None and session.sniffer.running)


def parse_tshark_live_line(line: str) -> PacketRecord:
    values = line.rstrip("\n").split("\t")
    if len(values) < len(TSHARK_FIELDS):
        values.extend([""] * (len(TSHARK_FIELDS) - len(values)))
    row = {
        field: (value.strip() or None)
        for field, value in zip(TSHARK_FIELDS, values[: len(TSHARK_FIELDS)])
    }
    return record_from_tshark_row(row)


def drain_available_records(
    session: LiveCaptureSession,
    max_lines: int = 500,
) -> tuple[list[PacketRecord], int]:
    """Read currently available capture records without waiting for future packets."""
    if session.backend == "tshark":
        return _drain_tshark_records(session, max_lines=max_lines)
    return _drain_scapy_records(session, max_lines=max_lines)


def _drain_tshark_records(
    session: LiveCaptureSession,
    max_lines: int = 500,
) -> tuple[list[PacketRecord], int]:
    stdout = session.process.stdout if session.process is not None else None
    if stdout is None:
        return [], 0

    records: list[PacketRecord] = []
    failed = 0
    for _ in range(max_lines):
        ready, _, _ = select.select([stdout], [], [], 0)
        if not ready:
            break

        line = stdout.readline()
        if not line:
            break
        if not line.strip():
            continue
        try:
            records.append(parse_tshark_live_line(line))
        except (TypeError, ValueError):
            failed += 1

    return records, failed


def _drain_scapy_records(
    session: LiveCaptureSession,
    max_lines: int = 500,
) -> tuple[list[PacketRecord], int]:
    if session.record_queue is None or session.failed_queue is None:
        return [], 0

    records: list[PacketRecord] = []
    for _ in range(max_lines):
        try:
            records.append(session.record_queue.get_nowait())
        except Empty:
            break

    failed = 0
    while True:
        try:
            failed += session.failed_queue.get_nowait()
        except Empty:
            break
    return records, failed


def drain_available_stderr(session: LiveCaptureSession, max_lines: int = 20) -> list[str]:
    if session.backend != "tshark" or session.process is None:
        return []

    stderr = session.process.stderr
    if stderr is None:
        return []

    lines: list[str] = []
    for _ in range(max_lines):
        ready, _, _ = select.select([stderr], [], [], 0)
        if not ready:
            break

        line = stderr.readline()
        if not line:
            break
        if line.strip():
            lines.append(line.strip())
    return lines


def append_rolling_records(
    existing: list[PacketRecord],
    new_records: list[PacketRecord],
    limit: int,
) -> list[PacketRecord]:
    if limit <= 0:
        return []
    return (existing + new_records)[-limit:]


def get_saved_pcap_bytes(session: LiveCaptureSession | None) -> bytes | None:
    if session is None:
        return None
    if session.backend == "tshark":
        return _read_tshark_pcap(session)
    return _build_scapy_pcap(session)


def _read_tshark_pcap(session: LiveCaptureSession) -> bytes | None:
    if not session.pcap_path:
        return None
    try:
        with open(session.pcap_path, "rb") as fh:
            data = fh.read()
    except OSError:
        return None
    return data or None


def _build_scapy_pcap(session: LiveCaptureSession) -> bytes | None:
    if session.raw_packet_queue is None or session.raw_packet_queue.empty():
        return None

    packets = list(session.raw_packet_queue.queue)
    path = _new_temp_pcap_path()
    try:
        wrpcap(path, packets)
        with open(path, "rb") as fh:
            data = fh.read()
    finally:
        _remove_file(path)
    return data or None


def cleanup_capture_artifacts(session: LiveCaptureSession | None) -> None:
    if session is not None and session.pcap_path:
        _remove_file(session.pcap_path)


def _new_temp_pcap_path() -> str:
    handle = tempfile.NamedTemporaryFile(suffix=".pcap", delete=False)
    handle.close()
    return handle.name


def _remove_file(path: str) -> None:
    try:
        import os

        os.unlink(path)
    except OSError:
        return
