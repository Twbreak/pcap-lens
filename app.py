import streamlit as st

st.set_page_config(
    page_title="PcapLens",
    page_icon="🔍",
    layout="wide",
)

from src.ui.live import live_page  # noqa: E402
from src.ui.pages import analyze_page, compare_page  # noqa: E402
from src.ui.settings import settings_page  # noqa: E402

navigation = st.navigation(
    [
        st.Page(analyze_page, title="Analyze", icon="🔍", default=True),
        st.Page(compare_page, title="Compare", icon="⚖️"),
        st.Page(live_page, title="Live", icon="📡"),
        st.Page(settings_page, title="Settings", icon="⚙️"),
    ]
)
navigation.run()
