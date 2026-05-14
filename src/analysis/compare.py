from typing import List, Tuple

import polars as pl

from src.analysis.summary import TrafficSummary
from src.config import TIME_BUCKET_SECONDS

# (display name, summary/dataframe) pairs — one entry per uploaded file
NamedSummary = Tuple[str, TrafficSummary]
NamedFrame = Tuple[str, pl.DataFrame]

_RELATIVE_TRAFFIC_SCHEMA = {
    "file": pl.String,
    "second": pl.Float64,
    "packet_count": pl.UInt32,
}


def build_comparison_table(named_summaries: List[NamedSummary]) -> pl.DataFrame:
    """Build a metric-by-file comparison table (rows = metrics, columns = files)."""
    columns: dict[str, list] = {
        "Metric": [
            "Total Packets",
            "Total Bytes",
            "Duration (s)",
            "Unique Source IPs",
            "Unique Destination IPs",
            "Top Protocol",
            "Top Source IP",
            "Top Destination Port",
        ]
    }
    for name, s in named_summaries:
        columns[name] = [
            f"{s.total_packets:,}",
            f"{s.total_bytes:,}",
            f"{s.duration_seconds:.2f}",
            str(s.unique_src_ips),
            str(s.unique_dst_ips),
            _first_key(s.protocol_distribution),
            _first_label(s.top_src_ips),
            _first_label(s.top_dst_ports),
        ]
    return pl.DataFrame(columns)


def build_relative_traffic(named_dfs: List[NamedFrame]) -> pl.DataFrame:
    """Long-form traffic counts with time normalized to seconds since each file's start.

    Returns columns: file, second, packet_count — so multiple captures can be
    overlaid on a shared x-axis even when they were recorded at different times.
    """
    frames = []
    for name, df in named_dfs:
        if df.is_empty():
            continue
        start = df["timestamp"].min()
        bucketed = (
            df.with_columns(
                (
                    ((pl.col("timestamp") - start) // TIME_BUCKET_SECONDS)
                    * TIME_BUCKET_SECONDS
                ).alias("second")
            )
            .group_by("second")
            .agg(pl.len().alias("packet_count"))
            .with_columns(pl.lit(name).alias("file"))
            .select("file", "second", "packet_count")
        )
        frames.append(bucketed)

    if not frames:
        return pl.DataFrame(schema=_RELATIVE_TRAFFIC_SCHEMA)
    return pl.concat(frames).sort(["file", "second"])


def _first_key(d: dict) -> str:
    return next(iter(d), "—")


def _first_label(pairs: list) -> str:
    return str(pairs[0][0]) if pairs else "—"
