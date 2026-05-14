from typing import Optional

import polars as pl


def filter_packets(
    df: pl.DataFrame,
    protocols: Optional[list[str]] = None,
    src_ip: Optional[str] = None,
    dst_ip: Optional[str] = None,
) -> pl.DataFrame:
    """Apply protocol and IP filters to a packet DataFrame.

    - protocols: keep only rows whose protocol is in this list (None = keep all)
    - src_ip / dst_ip: keep only rows whose IP contains this substring
      (None or empty = no filter)
    """
    result = df

    if protocols is not None:
        result = result.filter(pl.col("protocol").is_in(protocols))

    if src_ip:
        result = result.filter(
            pl.col("src_ip").is_not_null()
            & pl.col("src_ip").str.contains(src_ip, literal=True)
        )

    if dst_ip:
        result = result.filter(
            pl.col("dst_ip").is_not_null()
            & pl.col("dst_ip").str.contains(dst_ip, literal=True)
        )

    return result


def available_protocols(df: pl.DataFrame) -> list[str]:
    """Return the sorted list of distinct protocols present in the DataFrame."""
    if df.is_empty():
        return []
    return sorted(df["protocol"].unique().to_list())
