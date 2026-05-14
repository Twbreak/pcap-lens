import polars as pl


def to_csv_bytes(df: pl.DataFrame) -> bytes:
    """Serialize a packet DataFrame to CSV bytes (for download)."""
    return df.write_csv().encode("utf-8")


def to_json_bytes(df: pl.DataFrame) -> bytes:
    """Serialize a packet DataFrame to row-oriented JSON bytes (for download)."""
    return df.write_json(row_oriented=True).encode("utf-8")
