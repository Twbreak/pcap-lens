from dataclasses import dataclass

import polars as pl

from src.config import TOP_N

# scapy single-char TCP flags -> readable names
TCP_FLAG_NAMES = {
    "F": "FIN",
    "S": "SYN",
    "R": "RST",
    "P": "PSH",
    "A": "ACK",
    "U": "URG",
    "E": "ECE",
    "C": "CWR",
    "N": "NS",
}


@dataclass
class TrafficSummary:
    total_packets: int
    total_bytes: int
    duration_seconds: float
    unique_src_ips: int
    unique_dst_ips: int
    top_src_ips: list[tuple[str, int]]
    top_dst_ips: list[tuple[str, int]]
    top_dst_ports: list[tuple[int, int]]
    protocol_distribution: dict[str, int]
    tcp_flag_distribution: dict[str, int]
    top_dns_queries: list[tuple[str, int]]
    top_http_hosts: list[tuple[str, int]]
    http_method_distribution: dict[str, int]


def compute_summary(df: pl.DataFrame, top_n: int = TOP_N) -> TrafficSummary:
    """Compute traffic statistics from a packet DataFrame."""
    if df.is_empty():
        return TrafficSummary(
            total_packets=0,
            total_bytes=0,
            duration_seconds=0.0,
            unique_src_ips=0,
            unique_dst_ips=0,
            top_src_ips=[],
            top_dst_ips=[],
            top_dst_ports=[],
            protocol_distribution={},
            tcp_flag_distribution={},
            top_dns_queries=[],
            top_http_hosts=[],
            http_method_distribution={},
        )

    ts = df["timestamp"]
    duration = float(ts.max() - ts.min())

    return TrafficSummary(
        total_packets=len(df),
        total_bytes=int(df["length"].sum()),
        duration_seconds=duration,
        unique_src_ips=df["src_ip"].drop_nulls().n_unique(),
        unique_dst_ips=df["dst_ip"].drop_nulls().n_unique(),
        top_src_ips=_top_counts(df, "src_ip", limit=top_n),
        top_dst_ips=_top_counts(df, "dst_ip", limit=top_n),
        top_dst_ports=_top_counts(df, "dst_port", limit=top_n),
        protocol_distribution=dict(_top_counts(df, "protocol")),
        tcp_flag_distribution=_tcp_flag_distribution(df),
        top_dns_queries=_top_counts(df, "dns_qname", limit=top_n),
        top_http_hosts=_top_counts(df, "http_host", limit=top_n),
        http_method_distribution=dict(_top_counts(df, "http_method")),
    )


def _top_counts(df: pl.DataFrame, column: str, limit: int | None = None) -> list[tuple]:
    """Return (value, count) pairs for a column, sorted by count desc, nulls dropped."""
    grouped = (
        df.filter(pl.col(column).is_not_null())
        .group_by(column)
        .agg(pl.len().alias("count"))
        .sort("count", descending=True)
    )
    if limit is not None:
        grouped = grouped.head(limit)
    return list(zip(grouped[column].to_list(), grouped["count"].to_list()))


def _tcp_flag_distribution(df: pl.DataFrame) -> dict[str, int]:
    """Count individual TCP flags across all packets (e.g. 'SA' -> SYN +1, ACK +1)."""
    counts: dict[str, int] = {}
    for combo in df["tcp_flags"].drop_nulls().to_list():
        for ch in combo:
            name = TCP_FLAG_NAMES.get(ch, ch)
            counts[name] = counts.get(name, 0) + 1
    return dict(sorted(counts.items(), key=lambda kv: kv[1], reverse=True))
