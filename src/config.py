ALLOWED_EXTENSIONS = {".pcap"}
# App-level validation limit. Must stay <= Streamlit's server.maxUploadSize
# (see .streamlit/config.toml), otherwise the upload is rejected before we see it.
MAX_FILE_SIZE_MB = 200
MAX_FILE_SIZE_BYTES = MAX_FILE_SIZE_MB * 1024 * 1024

TABLE_DEFAULT_ROWS = 100
TOP_N = 10

CHART_HEIGHT = 400
CHART_COLOR_SEQUENCE = [
    "#636EFA", "#EF553B", "#00CC96", "#AB63FA", "#FFA15A",
    "#19D3F3", "#FF6692", "#B6E880", "#FF97FF", "#FECB52",
]
TIME_BUCKET_SECONDS = 1
