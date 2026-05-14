import json

import polars as pl

from src.analysis.export import to_csv_bytes, to_json_bytes
from src.transform.packet_table import SCHEMA


def test_csv_export_returns_bytes(sample_df):
    data = to_csv_bytes(sample_df)
    assert isinstance(data, bytes)
    text = data.decode("utf-8")
    assert "timestamp" in text
    assert "src_ip" in text
    # header + one line per record
    assert len(text.strip().splitlines()) == len(sample_df) + 1


def test_json_export_returns_bytes(sample_df):
    data = to_json_bytes(sample_df)
    assert isinstance(data, bytes)
    parsed = json.loads(data)
    assert isinstance(parsed, list)
    assert len(parsed) == len(sample_df)
    assert "protocol" in parsed[0]


def test_csv_export_empty_dataframe():
    empty = pl.DataFrame(schema=SCHEMA)
    data = to_csv_bytes(empty)
    assert isinstance(data, bytes)
    # header only
    assert data.decode("utf-8").strip().count("\n") == 0


def test_json_export_empty_dataframe():
    empty = pl.DataFrame(schema=SCHEMA)
    data = to_json_bytes(empty)
    assert json.loads(data) == []
