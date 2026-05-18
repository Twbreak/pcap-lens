from dataclasses import dataclass, field

import polars as pl

from src.analysis.insights import TrafficInsight
from src.analysis.summary import TrafficSummary


@dataclass(frozen=True)
class CaptureInput:
    """Raw capture bytes plus the display/source name."""

    data: bytes
    name: str


@dataclass(frozen=True)
class PacketFilters:
    """Packet table filters shared by UI, API, and future frontend clients."""

    protocols: tuple[str, ...] | None = None
    src_ip: str | None = None
    dst_ip: str | None = None


@dataclass(frozen=True)
class AnalyzeOptions:
    """Options that affect parser selection and analysis output."""

    backend_preference: str = "auto"
    top_n: int = 10
    local_ips: frozenset[str] = field(default_factory=frozenset)


@dataclass
class LoadedCapture:
    """Parsed capture in the canonical packet table shape."""

    name: str
    packets: pl.DataFrame
    failed_packets: int
    parser_backend: str


@dataclass
class AnalyzeResult:
    """Complete analysis result for one capture and one filter set."""

    capture: LoadedCapture
    filtered_packets: pl.DataFrame
    summary: TrafficSummary
    insights: list[TrafficInsight]


@dataclass
class CompareResult:
    """Comparison output for two or more successfully parsed captures."""

    captures: list[LoadedCapture]
    summaries: list[tuple[str, TrafficSummary]]
    table: pl.DataFrame
    relative_traffic: pl.DataFrame
