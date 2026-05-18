import subprocess
import time

import streamlit as st

from src.analysis.context import detect_local_ips
from src.analysis.insights import generate_insights
from src.analysis.summary import compute_summary
from src.capture.live_capture import (
    CaptureInterface,
    LiveCaptureSession,
    append_rolling_records,
    cleanup_capture_artifacts,
    drain_available_records,
    drain_available_stderr,
    get_saved_pcap_bytes,
    is_capture_running,
    list_capture_interfaces,
    resolve_live_backend,
    start_live_capture,
    stop_live_capture,
)
from src.domain.models import PacketRecord
from src.transform.packet_table import records_to_dataframe
from src.ui.i18n import t
from src.ui.sections import (
    render_charts,
    render_dns_http_section,
    render_filter_sidebar,
    render_insights,
    render_packet_table,
    render_parser_backend,
    render_summary_cards,
)
from src.ui.settings import get_packet_table_rows, get_top_n

LIVE_SESSION_KEY = "live_capture_session"
LIVE_RECORDS_KEY = "live_capture_records"
LIVE_FAILED_KEY = "live_capture_failed"
LIVE_ERRORS_KEY = "live_capture_errors"
LIVE_BACKEND_KEY = "live_backend_preference"
LIVE_PCAP_BYTES_KEY = "live_capture_pcap_bytes"
LIVE_PCAP_FILENAME_KEY = "live_capture_pcap_filename"

DEFAULT_ROLLING_LIMIT = 1000
ROLLING_LIMIT_OPTIONS = [500, 1000, 5000]
LIVE_BACKEND_OPTIONS = ["auto", "tshark", "scapy"]
REFRESH_INTERVAL_SECONDS = 1.0


def live_page() -> None:
    _init_live_state()

    st.title(t("live.title"))
    st.caption(t("live.caption"))

    session = _get_session()
    if session is not None:
        _drain_session(session)

    running = is_capture_running(_get_session())
    _render_controls(running)
    _render_status(running)
    _render_live_data()

    if running and st.session_state.get("live_auto_refresh", True):
        time.sleep(REFRESH_INTERVAL_SECONDS)
        st.rerun()


def _init_live_state() -> None:
    st.session_state.setdefault(LIVE_SESSION_KEY, None)
    st.session_state.setdefault(LIVE_RECORDS_KEY, [])
    st.session_state.setdefault(LIVE_FAILED_KEY, 0)
    st.session_state.setdefault(LIVE_ERRORS_KEY, [])
    st.session_state.setdefault(LIVE_BACKEND_KEY, "auto")
    st.session_state.setdefault(LIVE_PCAP_BYTES_KEY, None)
    st.session_state.setdefault(LIVE_PCAP_FILENAME_KEY, "live_capture.pcap")


@st.cache_data(show_spinner=False)
def _cached_interfaces(backend_preference: str) -> list[CaptureInterface]:
    return list_capture_interfaces(backend_preference)


def _render_controls(running: bool) -> None:
    backend_preference = _render_backend_selector(running)
    backend_status = resolve_live_backend(backend_preference)
    interfaces = _load_interfaces(backend_preference)

    col1, col2, col3 = st.columns([2, 1, 1])
    selected = col1.selectbox(
        t("live.interface"),
        interfaces,
        format_func=lambda iface: iface.label,
        disabled=running or not interfaces,
    )
    rolling_limit = col2.selectbox(
        t("live.rolling_packets"),
        ROLLING_LIMIT_OPTIONS,
        index=ROLLING_LIMIT_OPTIONS.index(DEFAULT_ROLLING_LIMIT),
        disabled=running,
    )
    col3.caption(t("live.actual_backend", backend=backend_status.backend))
    capture_filter = st.text_input(
        t("live.capture_filter"),
        placeholder="tcp port 80",
        disabled=running,
    )

    auto_refresh = st.checkbox(t("live.auto_refresh"), value=True, key="live_auto_refresh")

    start_col, stop_col, clear_col = st.columns(3)
    if start_col.button(
        t("live.start"),
        disabled=running or selected is None,
        use_container_width=True,
    ):
        _start_selected_capture(selected, capture_filter, rolling_limit, backend_preference)
        st.rerun()

    if stop_col.button(t("live.stop"), disabled=not running, use_container_width=True):
        _stop_current_capture()
        st.rerun()

    if clear_col.button(t("live.clear"), disabled=running, use_container_width=True):
        _clear_live_data()
        st.rerun()

    if not interfaces:
        st.warning(t("live.no_interfaces", backend=backend_status.backend))
    if not auto_refresh and running:
        st.caption(t("live.auto_refresh_off"))


def _render_backend_selector(running: bool) -> str:
    status = resolve_live_backend("auto")
    current = st.session_state[LIVE_BACKEND_KEY]
    if current == "tshark" and not status.tshark_available:
        st.session_state[LIVE_BACKEND_KEY] = "auto"
        current = "auto"

    cols = st.columns(3)
    for column, label, value, disabled in [
        (cols[0], "Auto", "auto", False),
        (cols[1], "tshark", "tshark", not status.tshark_available),
        (cols[2], "Scapy", "scapy", not status.scapy_available),
    ]:
        button_label = t("settings.backend_selected", label=label) if current == value else label
        if column.button(
            button_label,
            key=f"live_backend_{value}",
            disabled=running or disabled,
            use_container_width=True,
        ):
            st.session_state[LIVE_BACKEND_KEY] = value
            _cached_interfaces.clear()
            st.rerun()

    if not status.tshark_available:
        st.caption(t("live.tshark_unavailable"))
    return st.session_state[LIVE_BACKEND_KEY]


def _load_interfaces(backend_preference: str) -> list[CaptureInterface]:
    try:
        return _cached_interfaces(backend_preference)
    except (OSError, RuntimeError, subprocess.SubprocessError) as exc:
        st.error(t("live.interface_error", error=exc))
        return []


def _start_selected_capture(
    selected: CaptureInterface | None,
    capture_filter: str,
    rolling_limit: int,
    backend_preference: str,
) -> None:
    if selected is None:
        return
    _clear_saved_pcap()
    _clear_live_data()
    st.session_state["live_rolling_limit"] = rolling_limit
    try:
        st.session_state[LIVE_SESSION_KEY] = start_live_capture(
            selected,
            capture_filter,
            backend_preference=backend_preference,
        )
    except (OSError, RuntimeError) as exc:
        st.session_state[LIVE_ERRORS_KEY].append(str(exc))


def _stop_current_capture() -> None:
    session = _get_session()
    if session is not None:
        _drain_session(session)
        stop_live_capture(session)
        _store_saved_pcap(session)
        cleanup_capture_artifacts(session)
    st.session_state[LIVE_SESSION_KEY] = None


def _clear_live_data() -> None:
    cleanup_capture_artifacts(_get_session())
    st.session_state[LIVE_RECORDS_KEY] = []
    st.session_state[LIVE_FAILED_KEY] = 0
    st.session_state[LIVE_ERRORS_KEY] = []
    _clear_saved_pcap()


def _drain_session(session: LiveCaptureSession) -> None:
    new_records, failed = drain_available_records(session)
    errors = drain_available_stderr(session)

    limit = int(st.session_state.get("live_rolling_limit", DEFAULT_ROLLING_LIMIT))
    st.session_state[LIVE_RECORDS_KEY] = append_rolling_records(
        _get_records(),
        new_records,
        limit,
    )
    st.session_state[LIVE_FAILED_KEY] += failed
    st.session_state[LIVE_ERRORS_KEY].extend(errors)

    if not is_capture_running(session):
        st.session_state[LIVE_SESSION_KEY] = None


def _render_status(running: bool) -> None:
    session = _get_session()
    records = _get_records()

    status = t("live.status_capturing") if running else t("live.status_stopped")
    st.caption(t("live.status", status=status))
    render_parser_backend(session.backend if session is not None else "none")

    if session is not None:
        st.caption(t("live.interface_caption", interface=session.interface.label))
        if session.capture_filter:
            st.caption(t("live.capture_filter_caption", capture_filter=session.capture_filter))

    if st.session_state[LIVE_FAILED_KEY]:
        st.warning(t("live.parse_warning", count=st.session_state[LIVE_FAILED_KEY]))

    errors = st.session_state[LIVE_ERRORS_KEY]
    if errors:
        with st.expander(t("live.capture_messages")):
            for line in errors[-10:]:
                st.code(line)

    st.metric(t("live.buffered_packets"), f"{len(records):,}")
    _render_pcap_download()


def _render_live_data() -> None:
    records = _get_records()
    df = records_to_dataframe(records)
    filtered_df = render_filter_sidebar(df)
    summary = compute_summary(filtered_df, top_n=get_top_n())

    render_summary_cards(summary)
    render_insights(generate_insights(summary, local_ips=detect_local_ips()))
    render_charts(summary, filtered_df)
    render_dns_http_section(summary)
    render_packet_table(filtered_df, row_limit=get_packet_table_rows())


def _get_session() -> LiveCaptureSession | None:
    return st.session_state.get(LIVE_SESSION_KEY)


def _get_records() -> list[PacketRecord]:
    return st.session_state.get(LIVE_RECORDS_KEY, [])


def _store_saved_pcap(session: LiveCaptureSession) -> None:
    data = get_saved_pcap_bytes(session)
    if data is None:
        return
    timestamp = time.strftime("%Y%m%d_%H%M%S")
    backend = session.backend.lower()
    st.session_state[LIVE_PCAP_BYTES_KEY] = data
    st.session_state[LIVE_PCAP_FILENAME_KEY] = f"live_capture_{backend}_{timestamp}.pcap"


def _render_pcap_download() -> None:
    data = st.session_state.get(LIVE_PCAP_BYTES_KEY)
    if not data:
        return

    st.download_button(
        t("live.download_pcap"),
        data=data,
        file_name=st.session_state[LIVE_PCAP_FILENAME_KEY],
        mime="application/vnd.tcpdump.pcap",
        use_container_width=False,
    )


def _clear_saved_pcap() -> None:
    st.session_state[LIVE_PCAP_BYTES_KEY] = None
    st.session_state[LIVE_PCAP_FILENAME_KEY] = "live_capture.pcap"
