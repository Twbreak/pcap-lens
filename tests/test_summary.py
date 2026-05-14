import polars as pl
import pytest

from src.analysis.summary import compute_summary
from src.transform.packet_table import records_to_dataframe, SCHEMA


def test_total_packets(sample_df):
    summary = compute_summary(sample_df)
    assert summary.total_packets == len(sample_df)


def test_total_bytes(sample_df):
    summary = compute_summary(sample_df)
    assert summary.total_bytes == int(sample_df["length"].sum())


def test_duration(sample_df):
    summary = compute_summary(sample_df)
    expected = float(sample_df["timestamp"].max() - sample_df["timestamp"].min())
    assert abs(summary.duration_seconds - expected) < 1e-6


def test_unique_src_ips(sample_df):
    summary = compute_summary(sample_df)
    assert summary.unique_src_ips == sample_df["src_ip"].drop_nulls().n_unique()


def test_protocol_distribution(sample_df):
    summary = compute_summary(sample_df)
    assert "TCP" in summary.protocol_distribution
    assert summary.protocol_distribution["TCP"] == 2


def test_top_src_ips_sorted(sample_df):
    summary = compute_summary(sample_df)
    counts = [count for _, count in summary.top_src_ips]
    assert counts == sorted(counts, reverse=True)


def test_top_dst_ports(sample_df):
    summary = compute_summary(sample_df)
    ports = {port for port, _ in summary.top_dst_ports}
    # ARP row has null dst_port and is excluded
    assert ports == {80, 443, 53}
    counts = [count for _, count in summary.top_dst_ports]
    assert counts == sorted(counts, reverse=True)


def test_tcp_flag_distribution(sample_df):
    summary = compute_summary(sample_df)
    # TCP rows carry flags "S" and "SA" -> SYN x2, ACK x1
    assert summary.tcp_flag_distribution == {"SYN": 2, "ACK": 1}


def test_top_dns_queries(sample_df):
    summary = compute_summary(sample_df)
    assert summary.top_dns_queries == [("example.com", 1)]


def test_top_http_hosts(sample_df):
    summary = compute_summary(sample_df)
    assert summary.top_http_hosts == [("example.com", 1)]


def test_http_method_distribution(sample_df):
    summary = compute_summary(sample_df)
    assert summary.http_method_distribution == {"GET": 1}


def test_empty_dataframe():
    empty = pl.DataFrame(schema=SCHEMA)
    summary = compute_summary(empty)
    assert summary.total_packets == 0
    assert summary.total_bytes == 0
    assert summary.duration_seconds == 0.0
    assert summary.protocol_distribution == {}
    assert summary.top_src_ips == []
    assert summary.top_dst_ports == []
    assert summary.tcp_flag_distribution == {}
    assert summary.top_dns_queries == []
    assert summary.top_http_hosts == []
    assert summary.http_method_distribution == {}
