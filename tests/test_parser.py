import io
import subprocess

import src.parser.pcap_parser as parser
from src.domain.models import PacketRecord
from src.parser.pcap_parser import parse_pcap, parse_pcap_with_backend


def test_parse_returns_records(sample_pcap_bytes):
    records, failed = parse_pcap(io.BytesIO(sample_pcap_bytes))
    assert len(records) > 0
    assert all(isinstance(r, PacketRecord) for r in records)


def test_parse_extracts_ips(sample_pcap_bytes):
    records, _ = parse_pcap(io.BytesIO(sample_pcap_bytes))
    ips = {r.src_ip for r in records if r.src_ip}
    assert "192.168.1.1" in ips
    assert "192.168.1.2" in ips


def test_parse_extracts_ports(sample_pcap_bytes):
    records, _ = parse_pcap(io.BytesIO(sample_pcap_bytes))
    ports = {r.dst_port for r in records if r.dst_port}
    assert 80 in ports or 443 in ports


def test_parse_protocol_tcp(sample_pcap_bytes):
    records, _ = parse_pcap(io.BytesIO(sample_pcap_bytes))
    protocols = {r.protocol for r in records}
    assert "TCP" in protocols


def test_parse_extracts_tcp_flags(sample_pcap_bytes):
    # conftest builds TCP frames with the SYN flag set
    records, _ = parse_pcap(io.BytesIO(sample_pcap_bytes))
    tcp_records = [r for r in records if r.protocol == "TCP"]
    assert tcp_records
    assert all(r.tcp_flags == "S" for r in tcp_records)


def test_failed_count_is_zero_for_valid_pcap(sample_pcap_bytes):
    _, failed = parse_pcap(io.BytesIO(sample_pcap_bytes))
    assert failed == 0


def test_parse_extracts_dns_qname(dns_http_pcap_bytes):
    records, failed = parse_pcap(io.BytesIO(dns_http_pcap_bytes))
    assert failed == 0
    dns = [r for r in records if r.dns_qname]
    assert dns
    assert dns[0].dns_qname == "example.com"  # trailing dot stripped


def test_parse_extracts_http_host_and_method(dns_http_pcap_bytes):
    records, _ = parse_pcap(io.BytesIO(dns_http_pcap_bytes))
    http = [r for r in records if r.http_host]
    assert http
    assert http[0].http_host == "example.com"
    assert http[0].http_method == "GET"


def test_non_dns_http_packets_have_null_app_fields(sample_pcap_bytes):
    records, _ = parse_pcap(io.BytesIO(sample_pcap_bytes))
    # conftest's raw TCP SYN frames carry no DNS/HTTP payload
    assert all(r.dns_qname is None for r in records)
    assert all(r.http_host is None for r in records)


def test_parse_empty_pcap():
    import struct
    header = struct.pack("<IHHiIII", 0xA1B2C3D4, 2, 4, 0, 0, 65535, 1)
    records, failed = parse_pcap(io.BytesIO(header))
    assert records == []
    assert failed == 0


def test_parse_uses_tshark_backend_when_available(monkeypatch):
    output = (
        b"frame.time_epoch\tframe.len\tip.src\tipv6.src\tip.dst\tipv6.dst\t"
        b"tcp.srcport\tudp.srcport\ttcp.dstport\tudp.dstport\ttcp.flags\t"
        b"dns.qry.name\thttp.host\thttp.request.method\ticmp.type\tarp.opcode\n"
        b"1700000000.000000000\t60\t192.168.1.1\t\t10.0.0.1\t\t12345\t\t80\t\t"
        b"0x0002\t\t\t\t\t\n"
        b"1700000001.000000000\t71\t192.168.1.2\t\t8.8.8.8\t\t\t40000\t\t53\t"
        b"\texample.com\t\t\t\t\n"
    )
    calls = []

    def fake_run(cmd, check, capture_output):
        calls.append(cmd)
        return subprocess.CompletedProcess(cmd, 0, stdout=output, stderr=b"")

    monkeypatch.setattr(parser.shutil, "which", lambda name: "/usr/bin/tshark")
    monkeypatch.setattr(parser.subprocess, "run", fake_run)

    records, failed = parse_pcap(io.BytesIO(b"not inspected by mocked tshark"))

    assert failed == 0
    assert calls
    assert records[0] == PacketRecord(
        timestamp=1700000000.0,
        src_ip="192.168.1.1",
        dst_ip="10.0.0.1",
        protocol="TCP",
        src_port=12345,
        dst_port=80,
        length=60,
        tcp_flags="S",
    )
    assert records[1].protocol == "UDP"
    assert records[1].dns_qname == "example.com"

    records, failed, backend = parse_pcap_with_backend(
        io.BytesIO(b"not inspected by mocked tshark")
    )
    assert failed == 0
    assert backend == "tshark"
    assert records[0].protocol == "TCP"


def test_parse_falls_back_to_scapy_when_tshark_is_missing(monkeypatch):
    expected = [PacketRecord(1.0, None, None, "Other", None, None, 42)]

    monkeypatch.setattr(parser.shutil, "which", lambda name: None)
    monkeypatch.setattr(parser, "_parse_pcap_scapy", lambda source: (expected, 0))

    assert parse_pcap(io.BytesIO(b"pcap")) == (expected, 0)
    assert parse_pcap_with_backend(io.BytesIO(b"pcap")) == (expected, 0, "Scapy")


def test_forced_scapy_backend_skips_tshark(monkeypatch):
    expected = [PacketRecord(1.0, None, None, "Other", None, None, 42)]

    monkeypatch.setattr(parser.shutil, "which", lambda name: "/usr/bin/tshark")
    monkeypatch.setattr(parser, "_parse_pcap_scapy", lambda source: (expected, 0))
    monkeypatch.setattr(
        parser,
        "_parse_pcap_tshark",
        lambda source: (_ for _ in ()).throw(AssertionError("tshark should be skipped")),
    )

    assert parse_pcap_with_backend(
        io.BytesIO(b"pcap"),
        backend_preference="scapy",
    ) == (expected, 0, "Scapy")


def test_forced_tshark_backend_requires_tshark(monkeypatch):
    monkeypatch.setattr(parser.shutil, "which", lambda name: None)

    try:
        parse_pcap_with_backend(io.BytesIO(b"pcap"), backend_preference="tshark")
    except RuntimeError as exc:
        assert "tshark is not available" in str(exc)
    else:
        raise AssertionError("forced tshark backend should fail when tshark is unavailable")


def test_parse_falls_back_to_scapy_when_tshark_fails(monkeypatch):
    expected = [PacketRecord(1.0, None, None, "Other", None, None, 42)]

    def fake_run(cmd, check, capture_output):
        raise subprocess.CalledProcessError(1, cmd, stderr=b"bad capture")

    monkeypatch.setattr(parser.shutil, "which", lambda name: "/usr/bin/tshark")
    monkeypatch.setattr(parser.subprocess, "run", fake_run)
    monkeypatch.setattr(parser, "_parse_pcap_scapy", lambda source: (expected, 0))

    assert parse_pcap(io.BytesIO(b"pcap")) == (expected, 0)
    assert parse_pcap_with_backend(io.BytesIO(b"pcap")) == (expected, 0, "Scapy")
