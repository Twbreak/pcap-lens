import io
import logging
import os
import shutil
import subprocess
import tempfile

import polars as pl
from scapy.all import Packet, PcapReader
from scapy.layers.dns import DNSQR
from scapy.layers.http import HTTPRequest
from scapy.layers.inet import ICMP, IP, TCP, UDP
from scapy.layers.inet6 import IPv6
from scapy.layers.l2 import ARP

from src.domain.models import PacketRecord

logger = logging.getLogger(__name__)

TSHARK_FIELDS = [
    "frame.time_epoch",
    "frame.len",
    "ip.src",
    "ipv6.src",
    "ip.dst",
    "ipv6.dst",
    "tcp.srcport",
    "udp.srcport",
    "tcp.dstport",
    "udp.dstport",
    "tcp.flags",
    "dns.qry.name",
    "http.host",
    "http.request.method",
    "icmp.type",
    "arp.opcode",
]

ParserPreference = str


def is_tshark_available() -> bool:
    return shutil.which("tshark") is not None


def _decode(value) -> str | None:
    """Best-effort decode of a scapy bytes/str field to a clean str."""
    if value is None:
        return None
    if isinstance(value, bytes):
        value = value.decode("utf-8", errors="replace")
    return str(value).strip() or None


def _protocol_name(pkt: Packet) -> str:
    if pkt.haslayer(TCP):
        return "TCP"
    if pkt.haslayer(UDP):
        return "UDP"
    if pkt.haslayer(ICMP):
        return "ICMP"
    if pkt.haslayer(ARP):
        return "ARP"
    if pkt.haslayer(IPv6):
        return "IPv6"
    if pkt.haslayer(IP):
        return "IP"
    return "Other"


def _extract_ips(pkt: Packet) -> tuple[str | None, str | None]:
    if pkt.haslayer(IP):
        return pkt[IP].src, pkt[IP].dst
    if pkt.haslayer(IPv6):
        return pkt[IPv6].src, pkt[IPv6].dst
    return None, None


def _extract_ports(pkt: Packet) -> tuple[int | None, int | None]:
    if pkt.haslayer(TCP):
        return pkt[TCP].sport, pkt[TCP].dport
    if pkt.haslayer(UDP):
        return pkt[UDP].sport, pkt[UDP].dport
    return None, None


def _extract_tcp_flags(pkt: Packet) -> str | None:
    if pkt.haslayer(TCP):
        return str(pkt[TCP].flags)
    return None


def _extract_dns_qname(pkt: Packet) -> str | None:
    """Return the queried domain name from a DNS packet, without the trailing dot."""
    if not pkt.haslayer(DNSQR):
        return None
    qname = _decode(pkt[DNSQR].qname)
    return qname.rstrip(".") if qname else None


def _extract_http(pkt: Packet) -> tuple[str | None, str | None]:
    """Return (host, method) for an HTTP request packet."""
    if not pkt.haslayer(HTTPRequest):
        return None, None
    req = pkt[HTTPRequest]
    return _decode(req.Host), _decode(req.Method)


def parse_scapy_packet(pkt: Packet) -> PacketRecord | None:
    try:
        src_ip, dst_ip = _extract_ips(pkt)
        src_port, dst_port = _extract_ports(pkt)
        http_host, http_method = _extract_http(pkt)
        return PacketRecord(
            timestamp=float(pkt.time),
            src_ip=src_ip,
            dst_ip=dst_ip,
            protocol=_protocol_name(pkt),
            src_port=src_port,
            dst_port=dst_port,
            length=len(pkt),
            tcp_flags=_extract_tcp_flags(pkt),
            dns_qname=_extract_dns_qname(pkt),
            http_host=http_host,
            http_method=http_method,
        )
    except Exception as exc:
        logger.debug("Skipped unparseable packet: %s", exc)
        return None


def _parse_pcap_scapy(source: io.BytesIO | str) -> tuple[list[PacketRecord], int]:
    """Parse a pcap file with Scapy and return (records, failed_count)."""
    records: list[PacketRecord] = []
    failed = 0

    with PcapReader(source) as reader:
        for pkt in reader:
            record = parse_scapy_packet(pkt)
            if record is not None:
                records.append(record)
            else:
                failed += 1

    return records, failed


def _source_to_bytes(source: io.BytesIO | str) -> bytes:
    if isinstance(source, (str, os.PathLike)):
        with open(source, "rb") as fh:
            return fh.read()
    position = source.tell()
    try:
        source.seek(0)
        return source.read()
    finally:
        source.seek(position)


def _with_source_path(source: io.BytesIO | str):
    """Yield a filesystem path for tshark, writing in-memory uploads to a temp file."""
    if isinstance(source, (str, os.PathLike)):
        return _ExistingPath(str(source))
    return _TemporaryPcap(_source_to_bytes(source))


class _ExistingPath:
    def __init__(self, path: str):
        self.path = path

    def __enter__(self) -> str:
        return self.path

    def __exit__(self, exc_type, exc, tb) -> None:
        return None


class _TemporaryPcap:
    def __init__(self, data: bytes):
        self.data = data
        self.path: str | None = None

    def __enter__(self) -> str:
        with tempfile.NamedTemporaryFile(suffix=".pcap", delete=False) as fh:
            fh.write(self.data)
            self.path = fh.name
        return self.path

    def __exit__(self, exc_type, exc, tb) -> None:
        if self.path:
            os.unlink(self.path)


def _run_tshark(path: str) -> bytes:
    cmd = [
        "tshark",
        "-r",
        path,
        "-T",
        "fields",
        "-E",
        "header=y",
        "-E",
        "separator=/t",
        "-E",
        "occurrence=f",
    ]
    for field in TSHARK_FIELDS:
        cmd.extend(["-e", field])

    completed = subprocess.run(cmd, check=True, capture_output=True)
    return completed.stdout


def _read_tshark_fields(output: bytes) -> pl.DataFrame:
    schema = {field: pl.String for field in TSHARK_FIELDS}
    options = {
        "separator": "\t",
        "null_values": "",
    }
    try:
        return pl.read_csv(io.BytesIO(output), schema_overrides=schema, **options)
    except TypeError:
        return pl.read_csv(io.BytesIO(output), dtypes=schema, **options)


def _text(row: dict[str, str | None], field: str) -> str | None:
    value = row.get(field)
    if value is None:
        return None
    value = str(value).strip()
    return value or None


def _first_text(row: dict[str, str | None], *fields: str) -> str | None:
    for field in fields:
        value = _text(row, field)
        if value is not None:
            return value
    return None


def _int_or_none(row: dict[str, str | None], field: str) -> int | None:
    value = _text(row, field)
    if value is None:
        return None
    return int(value)


def _first_int(row: dict[str, str | None], *fields: str) -> int | None:
    for field in fields:
        value = _text(row, field)
        if value is not None:
            return int(value)
    return None


def _flags_from_tshark(value: str | None) -> str | None:
    if not value:
        return None
    mask = int(value, 16)
    flags = [
        (0x001, "F"),
        (0x002, "S"),
        (0x004, "R"),
        (0x008, "P"),
        (0x010, "A"),
        (0x020, "U"),
        (0x040, "E"),
        (0x080, "C"),
    ]
    return "".join(letter for bit, letter in flags if mask & bit) or None


def _protocol_from_tshark(row: dict[str, str | None]) -> str:
    if _text(row, "tcp.srcport") or _text(row, "tcp.dstport"):
        return "TCP"
    if _text(row, "udp.srcport") or _text(row, "udp.dstport"):
        return "UDP"
    if _text(row, "icmp.type"):
        return "ICMP"
    if _text(row, "arp.opcode"):
        return "ARP"
    if _text(row, "ipv6.src") or _text(row, "ipv6.dst"):
        return "IPv6"
    if _text(row, "ip.src") or _text(row, "ip.dst"):
        return "IP"
    return "Other"


def record_from_tshark_row(row: dict[str, str | None]) -> PacketRecord:
    return PacketRecord(
        timestamp=float(_text(row, "frame.time_epoch") or 0),
        src_ip=_first_text(row, "ip.src", "ipv6.src"),
        dst_ip=_first_text(row, "ip.dst", "ipv6.dst"),
        protocol=_protocol_from_tshark(row),
        src_port=_first_int(row, "tcp.srcport", "udp.srcport"),
        dst_port=_first_int(row, "tcp.dstport", "udp.dstport"),
        length=_int_or_none(row, "frame.len") or 0,
        tcp_flags=_flags_from_tshark(_text(row, "tcp.flags")),
        dns_qname=_text(row, "dns.qry.name"),
        http_host=_text(row, "http.host"),
        http_method=_text(row, "http.request.method"),
    )


def _parse_pcap_tshark(source: io.BytesIO | str) -> tuple[list[PacketRecord], int]:
    """Parse a pcap file with tshark fields output and Polars."""
    with _with_source_path(source) as path:
        df = _read_tshark_fields(_run_tshark(path))
    return [record_from_tshark_row(row) for row in df.iter_rows(named=True)], 0


def parse_pcap_with_backend(
    source: io.BytesIO | str,
    backend_preference: ParserPreference = "auto",
) -> tuple[list[PacketRecord], int, str]:
    """Parse a pcap file and return (records, failed_count, backend_name).

    Uses tshark's field extractor when available, with Scapy as the dependency-free
    fallback for environments without tshark.
    """
    if backend_preference not in {"auto", "tshark", "scapy"}:
        raise ValueError(f"Unknown parser backend preference: {backend_preference}")

    if backend_preference == "scapy":
        records, failed = _parse_pcap_scapy(source)
        return records, failed, "Scapy"

    if backend_preference == "tshark" and not is_tshark_available():
        raise RuntimeError("tshark parser selected, but tshark is not available on PATH")

    if is_tshark_available():
        try:
            records, failed = _parse_pcap_tshark(source)
            return records, failed, "tshark"
        except (OSError, subprocess.SubprocessError, pl.PolarsError, ValueError) as exc:
            if backend_preference == "tshark":
                raise RuntimeError(f"tshark parser failed: {exc}") from exc
            logger.warning("tshark parser failed; falling back to Scapy: %s", exc)
            if not isinstance(source, (str, os.PathLike)):
                source.seek(0)

    records, failed = _parse_pcap_scapy(source)
    return records, failed, "Scapy"


def parse_pcap(source: io.BytesIO | str) -> tuple[list[PacketRecord], int]:
    """Parse a pcap file and return (records, failed_count)."""
    records, failed, _backend = parse_pcap_with_backend(source)
    return records, failed
