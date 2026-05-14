import polars as pl
import streamlit as st

from src.analysis.charts import (
    comparison_protocol_chart,
    comparison_traffic_chart,
    protocol_distribution_chart,
    tcp_flags_chart,
    top_dst_ports_chart,
    top_src_ips_chart,
    traffic_over_time_chart,
)
from src.analysis.export import to_csv_bytes, to_json_bytes
from src.analysis.insights import TrafficInsight
from src.analysis.summary import TrafficSummary
from src.config import TABLE_DEFAULT_ROWS
from src.transform.filters import available_protocols, filter_packets


def render_upload_info(filename: str, size_mb: float) -> None:
    st.success(f"Loaded **{filename}** ({size_mb:.2f} MB)")


def render_parser_backend(backend: str) -> None:
    st.caption(f"Parser backend: `{backend}`")


def render_filter_sidebar(df: pl.DataFrame) -> pl.DataFrame:
    """Render filter controls in the sidebar and return the filtered DataFrame."""
    st.sidebar.header("Filters")

    if df.is_empty():
        st.sidebar.info("No packets to filter.")
        return df

    protocols = available_protocols(df)
    selected = st.sidebar.multiselect("Protocol", protocols, default=protocols)
    src_ip = st.sidebar.text_input("Source IP contains")
    dst_ip = st.sidebar.text_input("Destination IP contains")

    filtered = filter_packets(
        df,
        protocols=selected,
        src_ip=src_ip.strip() or None,
        dst_ip=dst_ip.strip() or None,
    )

    st.sidebar.caption(f"Showing {len(filtered):,} of {len(df):,} packets")
    return filtered


def render_parse_warning(failed: int) -> None:
    if failed > 0:
        st.warning(f"{failed} packet(s) could not be parsed and were skipped.")


def render_summary_cards(summary: TrafficSummary) -> None:
    st.subheader("Traffic Summary")

    col1, col2, col3 = st.columns(3)
    col1.metric("Total Packets", f"{summary.total_packets:,}")
    col2.metric("Total Bytes", _fmt_bytes(summary.total_bytes))
    col3.metric("Duration", f"{summary.duration_seconds:.2f}s")

    col4, col5 = st.columns(2)
    col4.metric("Unique Source IPs", summary.unique_src_ips)
    col5.metric("Unique Destination IPs", summary.unique_dst_ips)


def render_insights(insights: list[TrafficInsight]) -> None:
    st.subheader("Insights")

    for insight in insights:
        with st.container(border=True):
            st.markdown(f"**{insight.title}**")
            st.caption(f"Severity: `{insight.severity}`")
            st.write(insight.evidence)
            st.caption(insight.action)


def render_charts(summary: TrafficSummary, df: pl.DataFrame) -> None:
    st.subheader("Charts")

    st.plotly_chart(protocol_distribution_chart(summary), use_container_width=True)

    col1, col2 = st.columns(2)
    with col1:
        st.plotly_chart(top_src_ips_chart(summary), use_container_width=True)
    with col2:
        st.plotly_chart(top_dst_ports_chart(summary), use_container_width=True)

    st.plotly_chart(tcp_flags_chart(summary), use_container_width=True)
    st.plotly_chart(traffic_over_time_chart(df), use_container_width=True)


def render_dns_http_section(summary: TrafficSummary) -> None:
    st.subheader("DNS / HTTP")

    has_dns = bool(summary.top_dns_queries)
    has_http = bool(summary.top_http_hosts) or bool(summary.http_method_distribution)

    if not has_dns and not has_http:
        st.info("No DNS or HTTP traffic detected in this capture.")
        return

    col1, col2 = st.columns(2)

    with col1:
        st.markdown("**Top DNS Queries**")
        if has_dns:
            st.dataframe(
                pl.DataFrame(
                    summary.top_dns_queries, schema=["query", "count"], orient="row"
                ).to_pandas(),
                use_container_width=True,
                hide_index=True,
            )
        else:
            st.caption("No DNS queries.")

    with col2:
        st.markdown("**Top HTTP Hosts**")
        if summary.top_http_hosts:
            st.dataframe(
                pl.DataFrame(
                    summary.top_http_hosts, schema=["host", "count"], orient="row"
                ).to_pandas(),
                use_container_width=True,
                hide_index=True,
            )
        else:
            st.caption("No HTTP hosts.")

    if summary.http_method_distribution:
        methods = " · ".join(
            f"{m}: {c}" for m, c in summary.http_method_distribution.items()
        )
        st.caption(f"HTTP methods — {methods}")


def render_packet_table(df: pl.DataFrame, row_limit: int = TABLE_DEFAULT_ROWS) -> None:
    st.subheader(f"Packet Table (first {row_limit} rows)")

    if df.is_empty():
        st.info("No packets to display.")
        return

    display_df = df.head(row_limit).with_columns(
        pl.from_epoch("timestamp", time_unit="s").alias("timestamp")
    )
    st.dataframe(display_df.to_pandas(), use_container_width=True)


def render_export_section(df: pl.DataFrame) -> None:
    st.subheader("Export")

    if df.is_empty():
        st.info("Nothing to export.")
        return

    st.caption(f"Export all {len(df):,} filtered packets.")
    col1, col2 = st.columns(2)
    col1.download_button(
        "Download CSV",
        data=to_csv_bytes(df),
        file_name="packets.csv",
        mime="text/csv",
        use_container_width=True,
    )
    col2.download_button(
        "Download JSON",
        data=to_json_bytes(df),
        file_name="packets.json",
        mime="application/json",
        use_container_width=True,
    )


def render_comparison_table(table: pl.DataFrame) -> None:
    st.subheader("Metrics Comparison")
    st.dataframe(table.to_pandas(), use_container_width=True, hide_index=True)


def render_comparison_charts(
    named_summaries: list, relative_traffic: pl.DataFrame
) -> None:
    st.subheader("Comparison Charts")
    st.plotly_chart(
        comparison_protocol_chart(named_summaries), use_container_width=True
    )
    st.plotly_chart(
        comparison_traffic_chart(relative_traffic), use_container_width=True
    )


def _fmt_bytes(n: int) -> str:
    for unit in ("B", "KB", "MB", "GB"):
        if n < 1024:
            return f"{n:.1f} {unit}"
        n /= 1024
    return f"{n:.1f} TB"
