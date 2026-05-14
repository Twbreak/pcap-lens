import polars as pl

from src.domain.models import PacketRecord

SCHEMA = {
    "timestamp": pl.Float64,
    "src_ip": pl.String,
    "dst_ip": pl.String,
    "protocol": pl.String,
    "src_port": pl.Int32,
    "dst_port": pl.Int32,
    "length": pl.Int64,
    "tcp_flags": pl.String,
    "dns_qname": pl.String,
    "http_host": pl.String,
    "http_method": pl.String,
}


def records_to_dataframe(records: list[PacketRecord]) -> pl.DataFrame:
    """Convert a list of PacketRecord to a Polars DataFrame with a fixed schema."""
    if not records:
        return pl.DataFrame(schema=SCHEMA)

    return pl.DataFrame(
        {
            "timestamp": [r.timestamp for r in records],
            "src_ip": [r.src_ip for r in records],
            "dst_ip": [r.dst_ip for r in records],
            "protocol": [r.protocol for r in records],
            "src_port": [r.src_port for r in records],
            "dst_port": [r.dst_port for r in records],
            "length": [r.length for r in records],
            "tcp_flags": [r.tcp_flags for r in records],
            "dns_qname": [r.dns_qname for r in records],
            "http_host": [r.http_host for r in records],
            "http_method": [r.http_method for r in records],
        },
        schema=SCHEMA,
    )
