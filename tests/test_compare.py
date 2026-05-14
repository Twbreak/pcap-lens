import polars as pl
import plotly.graph_objects as go

from src.analysis.compare import build_comparison_table, build_relative_traffic
from src.analysis.summary import compute_summary
from src.analysis.charts import comparison_protocol_chart, comparison_traffic_chart
from src.transform.packet_table import SCHEMA


def test_comparison_table_has_metric_and_file_columns(sample_df, sample_df_2):
    named = [("a.pcap", compute_summary(sample_df)), ("b.pcap", compute_summary(sample_df_2))]
    table = build_comparison_table(named)
    assert table.columns == ["Metric", "a.pcap", "b.pcap"]
    assert table.height == 8  # eight metric rows


def test_comparison_table_total_packets_row(sample_df, sample_df_2):
    named = [("a.pcap", compute_summary(sample_df)), ("b.pcap", compute_summary(sample_df_2))]
    table = build_comparison_table(named)
    row = table.filter(pl.col("Metric") == "Total Packets")
    assert row["a.pcap"][0] == f"{len(sample_df):,}"
    assert row["b.pcap"][0] == f"{len(sample_df_2):,}"


def test_comparison_table_handles_empty_summary():
    empty = compute_summary(pl.DataFrame(schema=SCHEMA))
    table = build_comparison_table([("empty.pcap", empty)])
    top_proto = table.filter(pl.col("Metric") == "Top Protocol")["empty.pcap"][0]
    assert top_proto == "—"


def test_relative_traffic_long_form(sample_df, sample_df_2):
    rel = build_relative_traffic([("a.pcap", sample_df), ("b.pcap", sample_df_2)])
    assert rel.columns == ["file", "second", "packet_count"]
    assert set(rel["file"].unique().to_list()) == {"a.pcap", "b.pcap"}


def test_relative_traffic_starts_at_zero(sample_df):
    rel = build_relative_traffic([("a.pcap", sample_df)])
    # time is normalized to seconds since each file's own start
    assert rel["second"].min() == 0.0


def test_relative_traffic_skips_empty_frames(sample_df):
    empty = pl.DataFrame(schema=SCHEMA)
    rel = build_relative_traffic([("a.pcap", sample_df), ("empty.pcap", empty)])
    assert set(rel["file"].unique().to_list()) == {"a.pcap"}


def test_relative_traffic_all_empty():
    empty = pl.DataFrame(schema=SCHEMA)
    rel = build_relative_traffic([("empty.pcap", empty)])
    assert rel.is_empty()
    assert rel.columns == ["file", "second", "packet_count"]


def test_comparison_charts_return_figures(sample_df, sample_df_2):
    named = [("a.pcap", compute_summary(sample_df)), ("b.pcap", compute_summary(sample_df_2))]
    rel = build_relative_traffic([("a.pcap", sample_df), ("b.pcap", sample_df_2)])
    assert isinstance(comparison_protocol_chart(named), go.Figure)
    assert isinstance(comparison_traffic_chart(rel), go.Figure)


def test_comparison_charts_handle_empty():
    empty_rel = pl.DataFrame(
        schema={"file": pl.String, "second": pl.Float64, "packet_count": pl.UInt32}
    )
    assert isinstance(comparison_protocol_chart([]), go.Figure)
    assert isinstance(comparison_traffic_chart(empty_rel), go.Figure)
