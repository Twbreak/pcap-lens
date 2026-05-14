import io

import streamlit as st

from src.analysis.compare import build_comparison_table, build_relative_traffic
from src.analysis.context import detect_local_ips
from src.analysis.insights import generate_insights
from src.analysis.summary import compute_summary
from src.ingest.upload import validate_upload
from src.parser.pcap_parser import parse_pcap_with_backend
from src.transform.packet_table import SCHEMA, records_to_dataframe
from src.ui.sections import (
    render_charts,
    render_comparison_charts,
    render_comparison_table,
    render_dns_http_section,
    render_export_section,
    render_filter_sidebar,
    render_insights,
    render_packet_table,
    render_parse_warning,
    render_parser_backend,
    render_summary_cards,
    render_upload_info,
)
from src.ui.settings import (
    get_packet_table_rows,
    get_parser_backend_preference,
    get_top_n,
)

# Bound to the DataFrame schema so cached results are invalidated whenever the
# schema changes (e.g. a new column is added downstream of the cached function).
_SCHEMA_KEY = ",".join(SCHEMA.keys())


@st.cache_data(show_spinner="Parsing pcap…")
def _cached_parse(data: bytes, name: str, backend_preference: str):
    buf = io.BytesIO(data)
    buf.name = name
    return parse_pcap_with_backend(buf, backend_preference=backend_preference)


@st.cache_data(show_spinner=False)
def _cached_transform(
    data: bytes,
    name: str,
    backend_preference: str,
    schema_key: str = _SCHEMA_KEY,
):
    """Parse + transform once per file; filters are applied downstream on the result.

    `schema_key` is part of the cache key so a schema change forces a re-run.
    """
    records, failed, backend = _cached_parse(data, name, backend_preference)
    df = records_to_dataframe(records)
    return df, failed, backend


def analyze_page() -> None:
    """Single-file analysis: upload one pcap, filter, summarise, chart, export."""
    st.title("pcap-insight — Analyze")
    st.caption("Upload a .pcap file to get instant traffic summaries and charts.")

    uploaded = st.file_uploader("Choose a .pcap file", type=["pcap"])

    if uploaded is None:
        st.info("Upload a .pcap file to get started.")
        return

    try:
        file = validate_upload(uploaded)
    except ValueError as exc:
        st.error(str(exc))
        return

    render_upload_info(file.name, file.size_mb)

    try:
        df, failed, backend = _cached_transform(
            file.data,
            file.name,
            get_parser_backend_preference(),
        )
    except Exception as exc:
        st.error(f"Failed to parse the file: {exc}")
        return

    render_parser_backend(backend)
    render_parse_warning(failed)

    filtered_df = render_filter_sidebar(df)
    summary = compute_summary(filtered_df, top_n=get_top_n())

    render_summary_cards(summary)
    render_insights(generate_insights(summary, local_ips=detect_local_ips()))
    render_charts(summary, filtered_df)
    render_dns_http_section(summary)
    render_packet_table(filtered_df, row_limit=get_packet_table_rows())
    render_export_section(filtered_df)


def compare_page() -> None:
    """Multi-file comparison: upload two or more pcaps and compare them side by side."""
    st.title("pcap-insight — Compare")
    st.caption("Upload two or more .pcap files to compare their traffic side by side.")

    uploaded = st.file_uploader(
        "Choose .pcap files", type=["pcap"], accept_multiple_files=True
    )

    if not uploaded:
        st.info("Upload at least two .pcap files to compare.")
        return

    named_summaries = []
    named_dfs = []

    for up in uploaded:
        try:
            file = validate_upload(up)
        except ValueError as exc:
            st.error(f"{up.name}: {exc}")
            continue
        try:
            df, failed, backend = _cached_transform(
                file.data,
                file.name,
                get_parser_backend_preference(),
            )
        except Exception as exc:
            st.error(f"{up.name}: failed to parse — {exc}")
            continue
        st.caption(f"{file.name} parser backend: `{backend}`")
        if failed:
            st.warning(f"{file.name}: {failed} packet(s) skipped during parsing.")
        named_dfs.append((file.name, df))
        named_summaries.append((file.name, compute_summary(df, top_n=get_top_n())))

    if len(named_summaries) < 2:
        st.warning("Need at least two valid .pcap files to compare.")
        return

    render_comparison_table(build_comparison_table(named_summaries))
    render_comparison_charts(named_summaries, build_relative_traffic(named_dfs))
