import io
import struct
import pytest

from src.domain.models import PacketRecord
from src.transform.packet_table import records_to_dataframe


def make_pcap_bytes(packets: list[bytes]) -> bytes:
    """Build a minimal pcap byte stream from raw packet bytes."""
    MAGIC = 0xA1B2C3D4
    VERSION_MAJOR = 2
    VERSION_MINOR = 4
    THISZONE = 0
    SIGFIGS = 0
    SNAPLEN = 65535
    NETWORK = 1  # LINKTYPE_ETHERNET

    header = struct.pack(
        "<IHHiIII",
        MAGIC, VERSION_MAJOR, VERSION_MINOR, THISZONE, SIGFIGS, SNAPLEN, NETWORK,
    )

    records = b""
    ts = 1_700_000_000
    for i, pkt in enumerate(packets):
        ts_sec = ts + i
        ts_usec = 0
        inc_len = len(pkt)
        orig_len = len(pkt)
        records += struct.pack("<IIII", ts_sec, ts_usec, inc_len, orig_len) + pkt

    return header + records


def _eth_ip_tcp(src_ip: str, dst_ip: str, src_port: int, dst_port: int) -> bytes:
    """Build a minimal Ethernet/IP/TCP frame."""
    def ip_to_bytes(ip: str) -> bytes:
        return bytes(int(x) for x in ip.split("."))

    eth = b"\xff\xff\xff\xff\xff\xff" + b"\x00\x11\x22\x33\x44\x55" + b"\x08\x00"
    tcp_payload = b""
    tcp = (
        src_port.to_bytes(2, "big") + dst_port.to_bytes(2, "big")
        + b"\x00\x00\x00\x01"  # seq
        + b"\x00\x00\x00\x00"  # ack
        + b"\x50\x02"          # offset=5, SYN
        + b"\xff\xff"          # window
        + b"\x00\x00\x00\x00" # checksum + urgent
        + tcp_payload
    )
    total_len = 20 + len(tcp)
    ip = (
        b"\x45\x00"
        + total_len.to_bytes(2, "big")
        + b"\x00\x01\x40\x00\x40\x06\x00\x00"
        + ip_to_bytes(src_ip)
        + ip_to_bytes(dst_ip)
    )
    return eth + ip + tcp


@pytest.fixture
def sample_packets():
    return [
        _eth_ip_tcp("192.168.1.1", "10.0.0.1", 12345, 80),
        _eth_ip_tcp("192.168.1.2", "10.0.0.2", 54321, 443),
        _eth_ip_tcp("192.168.1.1", "10.0.0.1", 12346, 80),
    ]


@pytest.fixture
def sample_pcap_bytes(sample_packets):
    return make_pcap_bytes(sample_packets)


@pytest.fixture
def sample_records():
    return [
        PacketRecord(
            1700000000.0, "192.168.1.1", "10.0.0.1", "TCP", 12345, 80, 60, "S",
            http_host="example.com", http_method="GET",
        ),
        PacketRecord(1700000001.0, "192.168.1.2", "10.0.0.2", "TCP", 54321, 443, 80, "SA"),
        PacketRecord(
            1700000002.0, "192.168.1.1", "10.0.0.1", "UDP", 5353, 53, 40, None,
            dns_qname="example.com",
        ),
        PacketRecord(1700000003.0, None, None, "ARP", None, None, 28, None),
    ]


@pytest.fixture
def sample_df(sample_records):
    return records_to_dataframe(sample_records)


@pytest.fixture
def sample_records_2():
    """A second, distinct capture for multi-file comparison tests."""
    return [
        PacketRecord(1700001000.0, "172.16.0.1", "8.8.8.8", "UDP", 33333, 53, 50, None,
                     dns_qname="other.net"),
        PacketRecord(1700001002.0, "172.16.0.1", "1.1.1.1", "ICMP", None, None, 64, None),
        PacketRecord(1700001005.0, "172.16.0.2", "8.8.8.8", "UDP", 33334, 53, 50, None,
                     dns_qname="other.net"),
    ]


@pytest.fixture
def sample_df_2(sample_records_2):
    return records_to_dataframe(sample_records_2)


@pytest.fixture
def dns_http_pcap_bytes(tmp_path):
    """A pcap (built with scapy) containing one DNS query and one HTTP request."""
    from scapy.all import Ether, IP, TCP, UDP, wrpcap
    from scapy.layers.dns import DNS, DNSQR
    from scapy.layers.http import HTTP, HTTPRequest

    dns_pkt = (
        Ether()
        / IP(src="192.168.1.10", dst="8.8.8.8")
        / UDP(sport=40000, dport=53)
        / DNS(rd=1, qd=DNSQR(qname="example.com"))
    )
    http_pkt = (
        Ether()
        / IP(src="192.168.1.10", dst="93.184.216.34")
        / TCP(sport=40001, dport=80, flags="PA")
        / HTTP()
        / HTTPRequest(Method=b"GET", Host=b"example.com", Path=b"/")
    )
    path = tmp_path / "dns_http.pcap"
    wrpcap(str(path), [dns_pkt, http_pkt])
    return path.read_bytes()
