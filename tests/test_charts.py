import polars as pl
import pytest
import plotly.graph_objects as go

from src.analysis.charts import (
    protocol_distribution_chart,
    top_src_ips_chart,
    top_dst_ports_chart,
    tcp_flags_chart,
    traffic_over_time_chart,
)
from src.analysis.summary import compute_summary, TrafficSummary
from src.transform.packet_table import SCHEMA


def test_protocol_chart_returns_figure(sample_df):
    summary = compute_summary(sample_df)
    fig = protocol_distribution_chart(summary)
    assert isinstance(fig, go.Figure)


def test_top_src_chart_returns_figure(sample_df):
    summary = compute_summary(sample_df)
    fig = top_src_ips_chart(summary)
    assert isinstance(fig, go.Figure)


def test_traffic_over_time_returns_figure(sample_df):
    fig = traffic_over_time_chart(sample_df)
    assert isinstance(fig, go.Figure)


def test_top_dst_ports_chart_returns_figure(sample_df):
    summary = compute_summary(sample_df)
    fig = top_dst_ports_chart(summary)
    assert isinstance(fig, go.Figure)
    assert len(fig.data) > 0


def test_tcp_flags_chart_returns_figure(sample_df):
    summary = compute_summary(sample_df)
    fig = tcp_flags_chart(summary)
    assert isinstance(fig, go.Figure)
    assert len(fig.data) > 0


def test_empty_summary_charts_do_not_raise():
    empty_df = pl.DataFrame(schema=SCHEMA)
    empty_summary = compute_summary(empty_df)

    figs = [
        protocol_distribution_chart(empty_summary),
        top_src_ips_chart(empty_summary),
        top_dst_ports_chart(empty_summary),
        tcp_flags_chart(empty_summary),
        traffic_over_time_chart(empty_df),
    ]

    assert all(isinstance(f, go.Figure) for f in figs)


def test_protocol_chart_has_data(sample_df):
    summary = compute_summary(sample_df)
    fig = protocol_distribution_chart(summary)
    assert len(fig.data) > 0
