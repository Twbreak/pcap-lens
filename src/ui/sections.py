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
from src.core.schemas import PacketFilters
from src.transform.filters import available_protocols, filter_packets
from src.ui.i18n import t


def render_upload_info(filename: str, size_mb: float) -> None:
    st.success(t("sections.loaded", filename=filename, size_mb=size_mb))


def render_parser_backend(backend: str) -> None:
    st.caption(t("sections.parser_backend", backend=backend))


def render_filter_sidebar(df: pl.DataFrame) -> tuple[pl.DataFrame, PacketFilters]:
    """Render filter controls in the sidebar and return the filtered DataFrame."""
    st.sidebar.header(t("sections.filters"))

    if df.is_empty():
        st.sidebar.info(t("sections.no_packets_filter"))
        return df, PacketFilters()

    protocols = available_protocols(df)
    selected = st.sidebar.multiselect(t("sections.protocol"), protocols, default=protocols)
    src_ip = st.sidebar.text_input(t("sections.src_ip_contains"))
    dst_ip = st.sidebar.text_input(t("sections.dst_ip_contains"))
    filters = PacketFilters(
        protocols=tuple(selected),
        src_ip=src_ip.strip() or None,
        dst_ip=dst_ip.strip() or None,
    )

    filtered = filter_packets(
        df,
        protocols=list(filters.protocols) if filters.protocols is not None else None,
        src_ip=filters.src_ip,
        dst_ip=filters.dst_ip,
    )

    st.sidebar.caption(t("sections.showing_packets", filtered=len(filtered), total=len(df)))
    return filtered, filters


def render_parse_warning(failed: int) -> None:
    if failed > 0:
        st.warning(t("sections.parse_warning", count=failed))


def render_summary_cards(summary: TrafficSummary) -> None:
    st.subheader(t("sections.traffic_summary"))

    col1, col2, col3 = st.columns(3)
    col1.metric(t("sections.total_packets"), f"{summary.total_packets:,}")
    col2.metric(t("sections.total_bytes"), _fmt_bytes(summary.total_bytes))
    col3.metric(t("sections.duration"), f"{summary.duration_seconds:.2f}s")

    col4, col5 = st.columns(2)
    col4.metric(t("sections.unique_src_ips"), summary.unique_src_ips)
    col5.metric(t("sections.unique_dst_ips"), summary.unique_dst_ips)


def render_insights(insights: list[TrafficInsight]) -> None:
    st.subheader(t("sections.insights"))

    for insight in insights:
        title, evidence, action = _localize_insight(insight)
        with st.container(border=True):
            st.markdown(f"**{title}**")
            st.caption(t("sections.severity", severity=t(f"severity.{insight.severity}")))
            st.write(evidence)
            st.caption(action)


def _localize_insight(insight: TrafficInsight) -> tuple[str, str, str]:
    if not insight.message_key:
        return insight.title, insight.evidence, insight.action

    params = dict(insight.message_params)
    if insight.message_key == "http_activity":
        params["methods_text"] = (
            t("insight.http_activity.methods", methods=params["methods"])
            if params.get("methods")
            else ""
        )

    prefix = f"insight.{insight.message_key}"
    return (
        t(f"{prefix}.title", **params),
        t(f"{prefix}.evidence", **params),
        t(f"{prefix}.action", **params),
    )


def render_charts(summary: TrafficSummary, df: pl.DataFrame) -> None:
    st.subheader(t("sections.charts"))

    st.plotly_chart(protocol_distribution_chart(summary), use_container_width=True)

    col1, col2 = st.columns(2)
    with col1:
        st.plotly_chart(top_src_ips_chart(summary), use_container_width=True)
    with col2:
        st.plotly_chart(top_dst_ports_chart(summary), use_container_width=True)

    st.plotly_chart(tcp_flags_chart(summary), use_container_width=True)
    st.plotly_chart(traffic_over_time_chart(df), use_container_width=True)


def render_dns_http_section(summary: TrafficSummary) -> None:
    st.subheader(t("sections.dns_http"))

    has_dns = bool(summary.top_dns_queries)
    has_http = bool(summary.top_http_hosts) or bool(summary.http_method_distribution)

    if not has_dns and not has_http:
        st.info(t("sections.no_dns_http"))
        return

    col1, col2 = st.columns(2)

    with col1:
        st.markdown(f"**{t('sections.top_dns_queries')}**")
        if has_dns:
            st.dataframe(
                pl.DataFrame(
                    summary.top_dns_queries, schema=["query", "count"], orient="row"
                ).to_pandas(),
                use_container_width=True,
                hide_index=True,
            )
        else:
            st.caption(t("sections.no_dns_queries"))

    with col2:
        st.markdown(f"**{t('sections.top_http_hosts')}**")
        if summary.top_http_hosts:
            st.dataframe(
                pl.DataFrame(
                    summary.top_http_hosts, schema=["host", "count"], orient="row"
                ).to_pandas(),
                use_container_width=True,
                hide_index=True,
            )
        else:
            st.caption(t("sections.no_http_hosts"))

    if summary.http_method_distribution:
        methods = " · ".join(f"{m}: {c}" for m, c in summary.http_method_distribution.items())
        st.caption(t("sections.http_methods", methods=methods))


def render_packet_table(df: pl.DataFrame, row_limit: int = TABLE_DEFAULT_ROWS) -> None:
    st.subheader(t("sections.packet_table", row_limit=row_limit))

    if df.is_empty():
        st.info(t("sections.no_packets_display"))
        return

    display_df = df.head(row_limit).with_columns(
        pl.from_epoch("timestamp", time_unit="s").alias("timestamp")
    )
    st.dataframe(display_df.to_pandas(), use_container_width=True)


def render_export_section(df: pl.DataFrame) -> None:
    st.subheader(t("sections.export"))

    if df.is_empty():
        st.info(t("sections.nothing_to_export"))
        return

    st.caption(t("sections.export_all", count=len(df)))
    col1, col2 = st.columns(2)
    col1.download_button(
        t("sections.download_csv"),
        data=to_csv_bytes(df),
        file_name="packets.csv",
        mime="text/csv",
        use_container_width=True,
    )
    col2.download_button(
        t("sections.download_json"),
        data=to_json_bytes(df),
        file_name="packets.json",
        mime="application/json",
        use_container_width=True,
    )


def render_comparison_table(table: pl.DataFrame) -> None:
    st.subheader(t("sections.metrics_comparison"))
    st.dataframe(table.to_pandas(), use_container_width=True, hide_index=True)


def render_comparison_charts(named_summaries: list, relative_traffic: pl.DataFrame) -> None:
    st.subheader(t("sections.comparison_charts"))
    st.plotly_chart(comparison_protocol_chart(named_summaries), use_container_width=True)
    st.plotly_chart(comparison_traffic_chart(relative_traffic), use_container_width=True)


def _fmt_bytes(n: int) -> str:
    for unit in ("B", "KB", "MB", "GB"):
        if n < 1024:
            return f"{n:.1f} {unit}"
        n /= 1024
    return f"{n:.1f} TB"
