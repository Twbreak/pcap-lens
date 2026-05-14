from src.analysis.insights import generate_insights
from src.analysis.summary import compute_summary
from src.domain.models import PacketRecord
from src.transform.packet_table import records_to_dataframe


def test_empty_summary_generates_guidance():
    summary = compute_summary(records_to_dataframe([]))

    insights = generate_insights(summary)

    assert len(insights) == 1
    assert insights[0].severity == "info"
    assert insights[0].title == "No packets to inspect"


def test_top_talker_generates_notice(sample_records):
    summary = compute_summary(records_to_dataframe(sample_records))

    insights = generate_insights(summary)

    assert any(i.title == "One source dominates the capture" for i in insights)
    assert any("192.168.1.1" in i.evidence for i in insights)


def test_tcp_resets_generate_warning():
    records = [
        PacketRecord(1.0, "10.0.0.1", "10.0.0.2", "TCP", 1, 80, 60, "R"),
        PacketRecord(2.0, "10.0.0.2", "10.0.0.1", "TCP", 80, 1, 60, "R"),
        PacketRecord(3.0, "10.0.0.3", "10.0.0.4", "TCP", 2, 443, 60, "S"),
    ]
    summary = compute_summary(records_to_dataframe(records))

    insights = generate_insights(summary)

    reset = next(i for i in insights if i.title == "TCP resets observed")
    assert reset.severity == "warning"
    assert "RST appeared 2" in reset.evidence


def test_dns_and_http_insights(sample_records):
    summary = compute_summary(records_to_dataframe(sample_records))

    insights = generate_insights(summary)

    assert any(i.title == "DNS queries are present" for i in insights)
    assert any(i.title == "HTTP request traffic detected" for i in insights)


def test_no_notable_patterns_fallback():
    records = [
        PacketRecord(1.0, "10.0.0.1", "10.0.0.2", "ICMP", None, None, 60),
        PacketRecord(2.0, "10.0.0.2", "10.0.0.1", "ICMP", None, None, 60),
        PacketRecord(3.0, "10.0.0.3", "10.0.0.4", "ICMP", None, None, 60),
    ]
    summary = compute_summary(records_to_dataframe(records))

    insights = generate_insights(summary)

    assert len(insights) == 1
    assert insights[0].title == "No notable traffic patterns detected"


def test_local_top_destination_is_inbound_guidance_not_warning():
    records = [
        PacketRecord(float(i), f"10.0.0.{i}", "192.168.1.10", "TCP", 1234, 443, 60)
        for i in range(1, 5)
    ]
    records.append(PacketRecord(5.0, "10.0.0.5", "8.8.8.8", "TCP", 1234, 443, 60))
    summary = compute_summary(records_to_dataframe(records))

    insights = generate_insights(summary, local_ips={"192.168.1.10"})

    inbound = next(
        i for i in insights if i.title == "Most captured traffic is inbound to this host"
    )
    assert inbound.severity == "info"
    assert "appears to be local" in inbound.evidence
    assert not any(i.title == "Traffic concentrates on one destination" for i in insights)


def test_remote_top_destination_keeps_concentration_warning():
    records = [
        PacketRecord(float(i), f"10.0.0.{i}", "203.0.113.10", "TCP", 1234, 443, 60)
        for i in range(1, 5)
    ]
    records.append(PacketRecord(5.0, "10.0.0.5", "8.8.8.8", "TCP", 1234, 443, 60))
    summary = compute_summary(records_to_dataframe(records))

    insights = generate_insights(summary, local_ips={"192.168.1.10"})

    concentration = next(
        i for i in insights if i.title == "Traffic concentrates on one destination"
    )
    assert concentration.severity == "warning"
    assert "203.0.113.10 received" in concentration.evidence
