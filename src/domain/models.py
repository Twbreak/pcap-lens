from dataclasses import dataclass
from typing import Optional


@dataclass
class PacketRecord:
    timestamp: float
    src_ip: Optional[str]
    dst_ip: Optional[str]
    protocol: str
    src_port: Optional[int]
    dst_port: Optional[int]
    length: int
    tcp_flags: Optional[str] = None
    dns_qname: Optional[str] = None
    http_host: Optional[str] = None
    http_method: Optional[str] = None
