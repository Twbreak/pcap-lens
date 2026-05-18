import io

from src.core.schemas import AnalyzeOptions, CaptureInput, LoadedCapture, PacketFilters
from src.core.service import analyze_capture, analyze_packets, compare_captures, load_capture
from src.domain.models import PacketRecord
from src.transform.packet_table import records_to_dataframe


def test_load_capture_returns_canonical_dataframe(monkeypatch):
    expected = [PacketRecord(1.0, "192.168.1.1", "10.0.0.1", "TCP", 12345, 80, 60)]
    calls = []

    def fake_parse(source, backend_preference):
        calls.append((source, backend_preference))
        return expected, 0, "fake"

    monkeypatch.setattr("src.core.service.parse_pcap_with_backend", fake_parse)

    result = load_capture(CaptureInput(data=b"pcap", name="sample.pcap"), "scapy")

    assert result.name == "sample.pcap"
    assert result.failed_packets == 0
    assert result.parser_backend == "fake"
    assert result.packets.columns == records_to_dataframe(expected).columns
    assert isinstance(calls[0][0], io.BytesIO)
    assert calls[0][0].name == "sample.pcap"
    assert calls[0][1] == "scapy"


def test_analyze_packets_applies_filters_and_options(sample_df):
    capture = LoadedCapture(
        name="sample.pcap",
        packets=sample_df,
        failed_packets=0,
        parser_backend="test",
    )

    result = analyze_packets(
        capture,
        filters=PacketFilters(protocols=("TCP",), src_ip="192.168.1.1"),
        options=AnalyzeOptions(top_n=1),
    )

    assert result.capture is capture
    assert result.summary.total_packets == 1
    assert result.filtered_packets["protocol"].to_list() == ["TCP"]
    assert result.summary.top_src_ips == [("192.168.1.1", 1)]
    assert result.insights


def test_analyze_capture_composes_load_and_analyze(monkeypatch):
    records = [
        PacketRecord(1.0, "10.0.0.1", "8.8.8.8", "UDP", 12345, 53, 42, None),
        PacketRecord(2.0, "10.0.0.2", "1.1.1.1", "TCP", 12346, 443, 60, "S"),
    ]

    monkeypatch.setattr(
        "src.core.service.parse_pcap_with_backend",
        lambda source, backend_preference: (records, 0, backend_preference),
    )

    result = analyze_capture(
        CaptureInput(data=b"pcap", name="sample.pcap"),
        filters=PacketFilters(protocols=("UDP",)),
        options=AnalyzeOptions(backend_preference="scapy"),
    )

    assert result.capture.parser_backend == "scapy"
    assert result.summary.total_packets == 1
    assert result.filtered_packets["protocol"].to_list() == ["UDP"]


def test_compare_captures_builds_contract(sample_df, sample_df_2):
    captures = [
        LoadedCapture("a.pcap", sample_df, 0, "test"),
        LoadedCapture("b.pcap", sample_df_2, 0, "test"),
    ]

    result = compare_captures(captures, top_n=2)

    assert result.captures == captures
    assert [name for name, _summary in result.summaries] == ["a.pcap", "b.pcap"]
    assert result.table.columns == ["Metric", "a.pcap", "b.pcap"]
    assert set(result.relative_traffic["file"].unique().to_list()) == {"a.pcap", "b.pcap"}
