import streamlit as st

from src.analysis.context import detect_local_ips
from src.core.schemas import AnalyzeOptions, CaptureInput
from src.core.service import analyze_packets, compare_captures, load_capture
from src.ingest.upload import validate_upload
from src.transform.packet_table import SCHEMA
from src.ui.i18n import t
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
def _cached_load_capture(data: bytes, name: str, backend_preference: str, schema_key: str):
    return load_capture(
        CaptureInput(data=data, name=name),
        backend_preference=backend_preference,
    )


def analyze_page() -> None:
    """Single-file analysis: upload one pcap, filter, summarise, chart, export."""
    st.title(t("analyze.title"))
    st.caption(t("analyze.caption"))

    uploaded = st.file_uploader(t("analyze.upload_label"), type=["pcap"])

    if uploaded is None:
        st.info(t("analyze.upload_prompt"))
        return

    try:
        file = validate_upload(uploaded)
    except ValueError as exc:
        st.error(str(exc))
        return

    render_upload_info(file.name, file.size_mb)

    try:
        capture = _cached_load_capture(
            file.data,
            file.name,
            get_parser_backend_preference(),
            _SCHEMA_KEY,
        )
    except Exception as exc:
        st.error(t("analyze.parse_error", error=exc))
        return

    render_parser_backend(capture.parser_backend)
    render_parse_warning(capture.failed_packets)

    _filtered_preview, filters = render_filter_sidebar(capture.packets)
    result = analyze_packets(
        capture,
        filters=filters,
        options=AnalyzeOptions(
            top_n=get_top_n(),
            local_ips=frozenset(detect_local_ips()),
        ),
    )

    render_summary_cards(result.summary)
    render_insights(result.insights)
    render_charts(result.summary, result.filtered_packets)
    render_dns_http_section(result.summary)
    render_packet_table(result.filtered_packets, row_limit=get_packet_table_rows())
    render_export_section(result.filtered_packets)


def compare_page() -> None:
    """Multi-file comparison: upload two or more pcaps and compare them side by side."""
    st.title(t("compare.title"))
    st.caption(t("compare.caption"))

    uploaded = st.file_uploader(
        t("compare.upload_label"), type=["pcap"], accept_multiple_files=True
    )

    if not uploaded:
        st.info(t("compare.upload_prompt"))
        return

    captures = []

    for up in uploaded:
        try:
            file = validate_upload(up)
        except ValueError as exc:
            st.error(f"{up.name}: {exc}")
            continue
        try:
            capture = _cached_load_capture(
                file.data,
                file.name,
                get_parser_backend_preference(),
                _SCHEMA_KEY,
            )
        except Exception as exc:
            st.error(t("compare.file_parse_error", name=up.name, error=exc))
            continue
        st.caption(
            t("compare.backend_caption", name=capture.name, backend=capture.parser_backend)
        )
        if capture.failed_packets:
            st.warning(
                t("compare.skipped_packets", name=capture.name, count=capture.failed_packets)
            )
        captures.append(capture)

    if len(captures) < 2:
        st.warning(t("compare.need_two_files"))
        return

    result = compare_captures(captures, top_n=get_top_n())
    render_comparison_table(result.table)
    render_comparison_charts(result.summaries, result.relative_traffic)
