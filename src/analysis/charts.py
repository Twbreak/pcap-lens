import polars as pl
import plotly.graph_objects as go
import plotly.express as px

from src.analysis.summary import TrafficSummary
from src.config import CHART_HEIGHT, CHART_COLOR_SEQUENCE, TIME_BUCKET_SECONDS


def protocol_distribution_chart(summary: TrafficSummary) -> go.Figure:
    """Bar chart of packet count per protocol."""
    if not summary.protocol_distribution:
        return _empty_figure("No protocol data")

    protocols = list(summary.protocol_distribution.keys())
    counts = list(summary.protocol_distribution.values())

    fig = px.bar(
        x=protocols,
        y=counts,
        labels={"x": "Protocol", "y": "Packet Count"},
        title="Protocol Distribution",
        color=protocols,
        color_discrete_sequence=CHART_COLOR_SEQUENCE,
        height=CHART_HEIGHT,
    )
    fig.update_layout(showlegend=False)
    return fig


def top_src_ips_chart(summary: TrafficSummary) -> go.Figure:
    """Horizontal bar chart of top source IPs."""
    if not summary.top_src_ips:
        return _empty_figure("No source IP data")

    ips, counts = zip(*summary.top_src_ips)
    fig = px.bar(
        x=list(counts),
        y=list(ips),
        orientation="h",
        labels={"x": "Packet Count", "y": "Source IP"},
        title="Top Source IPs",
        color=list(ips),
        color_discrete_sequence=CHART_COLOR_SEQUENCE,
        height=CHART_HEIGHT,
    )
    fig.update_layout(showlegend=False, yaxis={"autorange": "reversed"})
    return fig


def top_dst_ports_chart(summary: TrafficSummary) -> go.Figure:
    """Bar chart of top destination ports."""
    if not summary.top_dst_ports:
        return _empty_figure("No destination port data")

    ports, counts = zip(*summary.top_dst_ports)
    labels = [str(p) for p in ports]
    fig = px.bar(
        x=labels,
        y=list(counts),
        labels={"x": "Destination Port", "y": "Packet Count"},
        title="Top Destination Ports",
        color=labels,
        color_discrete_sequence=CHART_COLOR_SEQUENCE,
        height=CHART_HEIGHT,
    )
    fig.update_layout(showlegend=False, xaxis_type="category")
    return fig


def tcp_flags_chart(summary: TrafficSummary) -> go.Figure:
    """Bar chart of TCP flag occurrences."""
    if not summary.tcp_flag_distribution:
        return _empty_figure("No TCP flag data")

    flags = list(summary.tcp_flag_distribution.keys())
    counts = list(summary.tcp_flag_distribution.values())
    fig = px.bar(
        x=flags,
        y=counts,
        labels={"x": "TCP Flag", "y": "Count"},
        title="TCP Flags Distribution",
        color=flags,
        color_discrete_sequence=CHART_COLOR_SEQUENCE,
        height=CHART_HEIGHT,
    )
    fig.update_layout(showlegend=False)
    return fig


def traffic_over_time_chart(df: pl.DataFrame) -> go.Figure:
    """Line chart of packet count per time bucket."""
    if df.is_empty():
        return _empty_figure("No traffic data")

    bucketed = (
        df.with_columns(
            (pl.col("timestamp") // TIME_BUCKET_SECONDS * TIME_BUCKET_SECONDS)
            .cast(pl.Float64)
            .alias("time_bucket")
        )
        .group_by("time_bucket")
        .agg(pl.len().alias("packet_count"), pl.col("length").sum().alias("total_bytes"))
        .sort("time_bucket")
        .with_columns(
            pl.from_epoch("time_bucket", time_unit="s").alias("time")
        )
    )

    fig = px.line(
        bucketed.to_pandas(),
        x="time",
        y="packet_count",
        labels={"time": "Time", "packet_count": "Packet Count"},
        title="Traffic Over Time",
        height=CHART_HEIGHT,
    )
    fig.update_traces(line_color=CHART_COLOR_SEQUENCE[0])
    return fig


def comparison_protocol_chart(named_summaries: list) -> go.Figure:
    """Grouped bar chart of protocol distribution across multiple files."""
    rows = [
        {"file": name, "protocol": proto, "count": count}
        for name, summary in named_summaries
        for proto, count in summary.protocol_distribution.items()
    ]
    if not rows:
        return _empty_figure("No protocol data")

    fig = px.bar(
        pl.DataFrame(rows).to_pandas(),
        x="protocol",
        y="count",
        color="file",
        barmode="group",
        labels={"protocol": "Protocol", "count": "Packet Count", "file": "File"},
        title="Protocol Distribution by File",
        color_discrete_sequence=CHART_COLOR_SEQUENCE,
        height=CHART_HEIGHT,
    )
    return fig


def comparison_traffic_chart(relative_traffic: pl.DataFrame) -> go.Figure:
    """Multi-line chart of traffic over time, one line per file (relative seconds)."""
    if relative_traffic.is_empty():
        return _empty_figure("No traffic data")

    fig = px.line(
        relative_traffic.to_pandas(),
        x="second",
        y="packet_count",
        color="file",
        labels={
            "second": "Seconds since capture start",
            "packet_count": "Packet Count",
            "file": "File",
        },
        title="Traffic Over Time by File",
        color_discrete_sequence=CHART_COLOR_SEQUENCE,
        height=CHART_HEIGHT,
    )
    return fig


def _empty_figure(message: str) -> go.Figure:
    fig = go.Figure()
    fig.add_annotation(
        text=message,
        xref="paper",
        yref="paper",
        x=0.5,
        y=0.5,
        showarrow=False,
        font={"size": 16},
    )
    fig.update_layout(height=CHART_HEIGHT)
    return fig
