import io

from src.analysis.compare import build_comparison_table, build_relative_traffic
from src.analysis.insights import generate_insights
from src.analysis.summary import compute_summary
from src.core.schemas import (
    AnalyzeOptions,
    AnalyzeResult,
    CaptureInput,
    CompareResult,
    LoadedCapture,
    PacketFilters,
)
from src.parser.pcap_parser import parse_pcap_with_backend
from src.transform.filters import filter_packets
from src.transform.packet_table import records_to_dataframe


def load_capture(capture: CaptureInput, backend_preference: str = "auto") -> LoadedCapture:
    """Parse capture bytes into the canonical packet DataFrame."""
    source = io.BytesIO(capture.data)
    source.name = capture.name
    records, failed, backend = parse_pcap_with_backend(
        source,
        backend_preference=backend_preference,
    )
    return LoadedCapture(
        name=capture.name,
        packets=records_to_dataframe(records),
        failed_packets=failed,
        parser_backend=backend,
    )


def analyze_packets(
    capture: LoadedCapture,
    filters: PacketFilters | None = None,
    options: AnalyzeOptions | None = None,
) -> AnalyzeResult:
    """Analyze an already parsed capture with the requested filter set."""
    filters = filters or PacketFilters()
    options = options or AnalyzeOptions()
    filtered = filter_packets(
        capture.packets,
        protocols=list(filters.protocols) if filters.protocols is not None else None,
        src_ip=filters.src_ip,
        dst_ip=filters.dst_ip,
    )
    summary = compute_summary(filtered, top_n=options.top_n)
    return AnalyzeResult(
        capture=capture,
        filtered_packets=filtered,
        summary=summary,
        insights=generate_insights(summary, local_ips=set(options.local_ips)),
    )


def analyze_capture(
    capture: CaptureInput,
    filters: PacketFilters | None = None,
    options: AnalyzeOptions | None = None,
) -> AnalyzeResult:
    """Parse and analyze one capture behind a stable application API."""
    options = options or AnalyzeOptions()
    loaded = load_capture(capture, backend_preference=options.backend_preference)
    return analyze_packets(loaded, filters=filters, options=options)


def compare_captures(
    captures: list[LoadedCapture],
    top_n: int = 10,
) -> CompareResult:
    """Build comparison data from parsed captures."""
    summaries = [
        (capture.name, compute_summary(capture.packets, top_n=top_n))
        for capture in captures
    ]
    named_dfs = [(capture.name, capture.packets) for capture in captures]
    return CompareResult(
        captures=captures,
        summaries=summaries,
        table=build_comparison_table(summaries),
        relative_traffic=build_relative_traffic(named_dfs),
    )
