import json

import polars as pl


def to_csv_bytes(df: pl.DataFrame) -> bytes:
    """Serialize a packet DataFrame to CSV bytes (for download)."""
    return df.write_csv().encode("utf-8")


def to_json_bytes(df: pl.DataFrame) -> bytes:
    """Serialize a packet DataFrame to row-oriented JSON bytes (for download)."""
    return json.dumps(df.to_dicts(), default=str).encode("utf-8")
