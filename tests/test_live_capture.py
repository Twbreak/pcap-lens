from queue import Queue

import src.capture.live_capture as live_capture
from src.capture.live_capture import (
    CaptureInterface,
    LiveCaptureSession,
    append_rolling_records,
    build_live_tshark_command,
    cleanup_capture_artifacts,
    drain_available_records,
    get_saved_pcap_bytes,
    list_scapy_capture_interfaces,
    parse_tshark_interfaces,
    parse_tshark_live_line,
    resolve_live_backend,
)
from src.domain.models import PacketRecord


def test_parse_tshark_interfaces():
    output = """
1. en0 (Wi-Fi)
2. lo0 (Loopback)
garbage
3. bridge0
"""

    assert parse_tshark_interfaces(output) == [
        CaptureInterface(id="1", label="en0 (Wi-Fi)"),
        CaptureInterface(id="2", label="lo0 (Loopback)"),
        CaptureInterface(id="3", label="bridge0"),
    ]


def test_build_live_tshark_command_includes_filter_and_fields():
    cmd = build_live_tshark_command("1", "tcp port 443", output_path="/tmp/live.pcap")

    assert cmd[:5] == ["tshark", "-i", "1", "-l", "-n"]
    assert ["-f", "tcp port 443"] == cmd[5:7]
    assert "-T" in cmd
    assert "fields" in cmd
    assert "frame.time_epoch" in cmd
    assert "http.request.method" in cmd
    assert cmd[-2:] == ["-w", "/tmp/live.pcap"]


def test_parse_tshark_live_line_to_packet_record():
    line = (
        "1700000000.000000000\t60\t192.168.1.1\t\t10.0.0.1\t\t"
        "12345\t\t80\t\t0x0002\t\t\t\t\t\n"
    )

    assert parse_tshark_live_line(line) == PacketRecord(
        timestamp=1700000000.0,
        src_ip="192.168.1.1",
        dst_ip="10.0.0.1",
        protocol="TCP",
        src_port=12345,
        dst_port=80,
        length=60,
        tcp_flags="S",
    )


def test_append_rolling_records_keeps_latest_packets():
    existing = [
        PacketRecord(1.0, None, None, "Other", None, None, 10),
        PacketRecord(2.0, None, None, "Other", None, None, 20),
    ]
    new = [
        PacketRecord(3.0, None, None, "Other", None, None, 30),
        PacketRecord(4.0, None, None, "Other", None, None, 40),
    ]

    assert append_rolling_records(existing, new, limit=3) == existing[1:] + new


def test_auto_live_backend_prefers_tshark(monkeypatch):
    monkeypatch.setattr(live_capture, "is_tshark_available", lambda: True)

    status = resolve_live_backend("auto")

    assert status.backend == "tshark"
    assert status.tshark_available is True
    assert status.scapy_available is True


def test_auto_live_backend_falls_back_to_scapy(monkeypatch):
    monkeypatch.setattr(live_capture, "is_tshark_available", lambda: False)

    status = resolve_live_backend("auto")

    assert status.backend == "scapy"
    assert status.tshark_available is False
    assert status.scapy_available is True


def test_forced_tshark_live_backend_requires_tshark(monkeypatch):
    monkeypatch.setattr(live_capture, "is_tshark_available", lambda: False)

    try:
        resolve_live_backend("tshark")
    except RuntimeError as exc:
        assert "tshark live capture selected" in str(exc)
    else:
        raise AssertionError("forced tshark live backend should require tshark")


def test_list_scapy_capture_interfaces(monkeypatch):
    monkeypatch.setattr(live_capture, "get_if_list", lambda: ["en0", "lo0"])

    assert list_scapy_capture_interfaces() == [
        CaptureInterface(id="en0", label="en0"),
        CaptureInterface(id="lo0", label="lo0"),
    ]


def test_drain_scapy_records_reads_queue_and_failures():
    record_queue = Queue()
    failed_queue = Queue()
    first = PacketRecord(1.0, None, None, "Other", None, None, 10)
    second = PacketRecord(2.0, None, None, "Other", None, None, 20)
    record_queue.put(first)
    record_queue.put(second)
    failed_queue.put(1)
    failed_queue.put(1)
    session = LiveCaptureSession(
        backend="Scapy",
        interface=CaptureInterface(id="en0", label="en0"),
        capture_filter="",
        record_queue=record_queue,
        failed_queue=failed_queue,
    )

    assert drain_available_records(session) == ([first, second], 2)


def test_get_saved_tshark_pcap_bytes(tmp_path):
    path = tmp_path / "capture.pcap"
    path.write_bytes(b"pcap-bytes")
    session = LiveCaptureSession(
        backend="tshark",
        interface=CaptureInterface(id="1", label="en0"),
        capture_filter="",
        pcap_path=str(path),
    )

    assert get_saved_pcap_bytes(session) == b"pcap-bytes"


def test_cleanup_capture_artifacts_removes_tshark_pcap(tmp_path):
    path = tmp_path / "capture.pcap"
    path.write_bytes(b"pcap-bytes")
    session = LiveCaptureSession(
        backend="tshark",
        interface=CaptureInterface(id="1", label="en0"),
        capture_filter="",
        pcap_path=str(path),
    )

    cleanup_capture_artifacts(session)

    assert not path.exists()


def test_get_saved_scapy_pcap_bytes():
    from scapy.all import IP, TCP, Ether

    raw_packet_queue = Queue()
    raw_packet_queue.put(Ether() / IP(src="192.168.1.1", dst="10.0.0.1") / TCP())
    session = LiveCaptureSession(
        backend="Scapy",
        interface=CaptureInterface(id="en0", label="en0"),
        capture_filter="",
        raw_packet_queue=raw_packet_queue,
    )

    data = get_saved_pcap_bytes(session)

    assert data is not None
    assert data[:4] in {b"\xd4\xc3\xb2\xa1", b"\xa1\xb2\xc3\xd4"}
