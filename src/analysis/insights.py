from dataclasses import dataclass

from src.analysis.summary import TrafficSummary


@dataclass(frozen=True)
class TrafficInsight:
    severity: str
    title: str
    evidence: str
    action: str


def generate_insights(
    summary: TrafficSummary,
    local_ips: set[str] | None = None,
) -> list[TrafficInsight]:
    """Generate deterministic, explainable traffic observations from a summary."""
    local_ips = local_ips or set()
    if summary.total_packets == 0:
        return [
            TrafficInsight(
                severity="info",
                title="No packets to inspect",
                evidence="The current view contains 0 packets.",
                action="Upload a capture, start live capture, or loosen active filters.",
            )
        ]

    insights: list[TrafficInsight] = []
    insights.extend(_top_talker(summary))
    insights.extend(_top_destination(summary, local_ips))
    insights.extend(_dns_activity(summary))
    insights.extend(_http_activity(summary))
    insights.extend(_tcp_resets(summary))
    insights.extend(_high_port_activity(summary))

    if not insights:
        insights.append(
            TrafficInsight(
                severity="info",
                title="No notable traffic patterns detected",
                evidence=f"Reviewed {summary.total_packets:,} packets with current rules.",
                action="Use filters or inspect the packet table for protocol-specific details.",
            )
        )
    return insights


def _top_talker(summary: TrafficSummary) -> list[TrafficInsight]:
    if not summary.top_src_ips:
        return []

    ip, count = summary.top_src_ips[0]
    share = _share(count, summary.total_packets)
    if share < 40:
        return []

    return [
        TrafficInsight(
            severity="warning" if share >= 70 else "notice",
            title="One source dominates the capture",
            evidence=f"{ip} sent {count:,} packets ({share:.1f}% of this view).",
            action=f"Filter source IP contains {ip} and inspect destinations and ports.",
        )
    ]


def _top_destination(summary: TrafficSummary, local_ips: set[str]) -> list[TrafficInsight]:
    if not summary.top_dst_ips:
        return []

    ip, count = summary.top_dst_ips[0]
    share = _share(count, summary.total_packets)
    if share < 40:
        return []

    if ip in local_ips:
        return [
            TrafficInsight(
                severity="info",
                title="Most captured traffic is inbound to this host",
                evidence=(
                    f"{ip} appears to be local and received {count:,} packets "
                    f"({share:.1f}% of this view)."
                ),
                action=(
                    "Review top source IPs and destination ports to understand "
                    "inbound services."
                ),
            )
        ]

    return [
        TrafficInsight(
            severity="warning" if share >= 70 else "notice",
            title="Traffic concentrates on one destination",
            evidence=f"{ip} received {count:,} packets ({share:.1f}% of this view).",
            action=f"Filter destination IP contains {ip} and review protocols involved.",
        )
    ]


def _dns_activity(summary: TrafficSummary) -> list[TrafficInsight]:
    dns_count = summary.protocol_distribution.get("UDP", 0)
    if not summary.top_dns_queries:
        return []

    query, count = summary.top_dns_queries[0]
    return [
        TrafficInsight(
            severity="notice",
            title="DNS queries are present",
            evidence=f"Top DNS query is {query} with {count:,} occurrence(s).",
            action=f"Review repeated DNS lookups for {query}; UDP packets in view: {dns_count:,}.",
        )
    ]


def _http_activity(summary: TrafficSummary) -> list[TrafficInsight]:
    if not summary.top_http_hosts and not summary.http_method_distribution:
        return []

    host_text = "unknown host"
    if summary.top_http_hosts:
        host, count = summary.top_http_hosts[0]
        host_text = f"{host} ({count:,} request packet(s))"

    methods = ", ".join(
        f"{method}: {count}" for method, count in summary.http_method_distribution.items()
    )
    evidence = f"Top HTTP host is {host_text}."
    if methods:
        evidence += f" Methods: {methods}."

    return [
        TrafficInsight(
            severity="info",
            title="HTTP request traffic detected",
            evidence=evidence,
            action="Inspect HTTP hosts and methods before sharing captures externally.",
        )
    ]


def _tcp_resets(summary: TrafficSummary) -> list[TrafficInsight]:
    resets = summary.tcp_flag_distribution.get("RST", 0)
    if resets == 0:
        return []

    tcp_packets = summary.protocol_distribution.get("TCP", summary.total_packets)
    share = _share(resets, tcp_packets)
    return [
        TrafficInsight(
            severity="warning" if share >= 10 else "notice",
            title="TCP resets observed",
            evidence=f"RST appeared {resets:,} time(s), about {share:.1f}% of TCP packets.",
            action=(
                "Check whether resets align with failed connections, blocked ports, "
                "or service restarts."
            ),
        )
    ]


def _high_port_activity(summary: TrafficSummary) -> list[TrafficInsight]:
    high_ports = [(port, count) for port, count in summary.top_dst_ports if int(port) >= 49152]
    if not high_ports:
        return []

    port, count = high_ports[0]
    return [
        TrafficInsight(
            severity="info",
            title="High destination port activity",
            evidence=f"Port {port} appears {count:,} time(s) among top destination ports.",
            action=(
                "Confirm whether this is expected ephemeral-port or "
                "application-specific traffic."
            ),
        )
    ]


def _share(count: int, total: int) -> float:
    if total <= 0:
        return 0.0
    return count / total * 100
