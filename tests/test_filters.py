import polars as pl

from src.transform.filters import filter_packets, available_protocols
from src.transform.packet_table import SCHEMA


def test_no_filters_returns_all(sample_df):
    result = filter_packets(sample_df)
    assert len(result) == len(sample_df)


def test_protocol_filter(sample_df):
    result = filter_packets(sample_df, protocols=["TCP"])
    assert len(result) == 2
    assert set(result["protocol"].to_list()) == {"TCP"}


def test_protocol_filter_multiple(sample_df):
    result = filter_packets(sample_df, protocols=["TCP", "UDP"])
    assert set(result["protocol"].to_list()) == {"TCP", "UDP"}


def test_protocol_filter_empty_list(sample_df):
    result = filter_packets(sample_df, protocols=[])
    assert len(result) == 0


def test_src_ip_filter_exact(sample_df):
    # sample_df has two rows with src_ip 192.168.1.1
    result = filter_packets(sample_df, src_ip="192.168.1.1")
    assert len(result) == 2
    assert set(result["src_ip"].to_list()) == {"192.168.1.1"}


def test_src_ip_filter_substring(sample_df):
    # matches 192.168.1.1 (x2) and 192.168.1.2
    result = filter_packets(sample_df, src_ip="192.168")
    assert len(result) == 3


def test_dst_ip_filter(sample_df):
    # two rows have dst_ip 10.0.0.1
    result = filter_packets(sample_df, dst_ip="10.0.0.1")
    assert len(result) == 2
    assert set(result["dst_ip"].to_list()) == {"10.0.0.1"}


def test_combined_filters(sample_df):
    result = filter_packets(sample_df, protocols=["TCP"], src_ip="192.168.1.2")
    assert len(result) == 1
    assert result["protocol"].to_list() == ["TCP"]


def test_ip_filter_excludes_nulls(sample_df):
    # sample_df has an ARP row with null src_ip
    result = filter_packets(sample_df, src_ip="192")
    assert result["src_ip"].null_count() == 0


def test_available_protocols(sample_df):
    assert available_protocols(sample_df) == ["ARP", "TCP", "UDP"]


def test_available_protocols_empty():
    empty = pl.DataFrame(schema=SCHEMA)
    assert available_protocols(empty) == []


def test_filter_empty_dataframe():
    empty = pl.DataFrame(schema=SCHEMA)
    result = filter_packets(empty, protocols=["TCP"], src_ip="1.2.3.4")
    assert len(result) == 0
