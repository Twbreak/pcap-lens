import importlib.metadata

import streamlit as st

from src.config import TABLE_DEFAULT_ROWS, TOP_N
from src.parser.pcap_parser import is_tshark_available

PARSER_BACKEND_KEY = "settings_parser_backend"
PACKET_TABLE_ROWS_KEY = "settings_packet_table_rows"
TOP_N_KEY = "settings_top_n"

PARSER_BACKEND_DEFAULT = "auto"
PACKET_TABLE_ROW_OPTIONS = [50, 100, 250, 500]
TOP_N_OPTIONS = [5, 10, 20]


def init_settings() -> None:
    st.session_state.setdefault(PARSER_BACKEND_KEY, PARSER_BACKEND_DEFAULT)
    st.session_state.setdefault(PACKET_TABLE_ROWS_KEY, TABLE_DEFAULT_ROWS)
    st.session_state.setdefault(TOP_N_KEY, TOP_N)


def get_parser_backend_preference() -> str:
    init_settings()
    return st.session_state[PARSER_BACKEND_KEY]


def get_packet_table_rows() -> int:
    init_settings()
    return int(st.session_state[PACKET_TABLE_ROWS_KEY])


def get_top_n() -> int:
    init_settings()
    return int(st.session_state[TOP_N_KEY])


def settings_page() -> None:
    init_settings()

    st.title("PcapLens - Settings")
    st.caption("Tune parser behavior and display limits for the current session.")

    _render_parser_settings()
    _render_display_settings()
    _render_cache_controls()
    _render_environment_status()


def _render_parser_settings() -> None:
    st.subheader("Parser")

    tshark_available = is_tshark_available()
    current = st.session_state[PARSER_BACKEND_KEY]
    if current == "tshark" and not tshark_available:
        st.session_state[PARSER_BACKEND_KEY] = "auto"
        current = "auto"

    cols = st.columns(3)
    _backend_button(cols[0], "Auto", "auto", current, disabled=False)
    _backend_button(cols[1], "tshark", "tshark", current, disabled=not tshark_available)
    _backend_button(cols[2], "Scapy", "scapy", current, disabled=False)

    if not tshark_available:
        st.caption("tshark is not available on PATH, so that option is disabled.")


def _backend_button(column, label: str, value: str, current: str, disabled: bool) -> None:
    selected = current == value
    button_label = f"{label} selected" if selected else label
    if column.button(
        button_label,
        key=f"parser_backend_{value}",
        disabled=disabled,
        use_container_width=True,
    ):
        st.session_state[PARSER_BACKEND_KEY] = value
        st.cache_data.clear()
        st.rerun()


def _render_display_settings() -> None:
    st.subheader("Display")

    rows_index = _option_index(PACKET_TABLE_ROW_OPTIONS, get_packet_table_rows())
    top_n_index = _option_index(TOP_N_OPTIONS, get_top_n())

    col1, col2 = st.columns(2)
    st.session_state[PACKET_TABLE_ROWS_KEY] = col1.selectbox(
        "Packet table rows",
        PACKET_TABLE_ROW_OPTIONS,
        index=rows_index,
    )
    st.session_state[TOP_N_KEY] = col2.selectbox(
        "Top-N charts and summaries",
        TOP_N_OPTIONS,
        index=top_n_index,
    )


def _render_cache_controls() -> None:
    st.subheader("Cache")
    if st.button("Clear parse cache", use_container_width=False):
        st.cache_data.clear()
        st.success("Parse cache cleared.")


def _render_environment_status() -> None:
    st.subheader("Environment")

    tshark_status = "available" if is_tshark_available() else "unavailable"
    st.write(f"tshark: `{tshark_status}`")
    st.write("Scapy: `available`")
    st.write(f"Polars: `{_package_version('polars')}`")


def _package_version(package: str) -> str:
    try:
        return importlib.metadata.version(package)
    except importlib.metadata.PackageNotFoundError:
        return "unknown"


def _option_index(options: list[int], value: int) -> int:
    try:
        return options.index(value)
    except ValueError:
        return 0
