import streamlit as st

LANGUAGE_KEY = "settings_language"
DEFAULT_LANGUAGE = "en"

LANGUAGE_OPTIONS = {
    "en": "English",
    "zh-TW": "繁體中文",
}

TRANSLATIONS = {
    "en": {
        "app.analyze": "Analyze",
        "app.compare": "Compare",
        "app.live": "Live",
        "app.settings": "Settings",
        "analyze.title": "PcapLens - Analyze",
        "analyze.caption": "Upload a .pcap file to get instant traffic summaries and charts.",
        "analyze.upload_label": "Choose a .pcap file",
        "analyze.upload_prompt": "Upload a .pcap file to get started.",
        "analyze.parse_error": "Failed to parse the file: {error}",
        "compare.title": "PcapLens - Compare",
        "compare.caption": "Upload two or more .pcap files to compare their traffic side by side.",
        "compare.upload_label": "Choose .pcap files",
        "compare.upload_prompt": "Upload at least two .pcap files to compare.",
        "compare.file_parse_error": "{name}: failed to parse - {error}",
        "compare.backend_caption": "{name} parser backend: `{backend}`",
        "compare.skipped_packets": "{name}: {count} packet(s) skipped during parsing.",
        "compare.need_two_files": "Need at least two valid .pcap files to compare.",
        "live.title": "PcapLens - Live",
        "live.caption": (
            "Capture live traffic with tshark or Scapy and inspect it as packets arrive."
        ),
        "live.interface": "Interface",
        "live.rolling_packets": "Rolling packets",
        "live.actual_backend": "Actual backend: `{backend}`",
        "live.capture_filter": "Capture filter",
        "live.auto_refresh": "Auto-refresh",
        "live.start": "Start",
        "live.stop": "Stop",
        "live.clear": "Clear",
        "live.no_interfaces": "No {backend} capture interfaces were found.",
        "live.auto_refresh_off": (
            "Auto-refresh is off; use Streamlit rerun controls to refresh packets."
        ),
        "live.tshark_unavailable": "tshark is unavailable; Auto will use Scapy.",
        "live.interface_error": "Failed to list capture interfaces: {error}",
        "live.status": "Status: `{status}`",
        "live.status_capturing": "capturing",
        "live.status_stopped": "stopped",
        "live.interface_caption": "Interface: `{interface}`",
        "live.capture_filter_caption": "Capture filter: `{capture_filter}`",
        "live.parse_warning": "{count} live packet line(s) could not be parsed.",
        "live.capture_messages": "Capture messages",
        "live.buffered_packets": "Buffered Packets",
        "live.download_pcap": "Download PCAP",
        "settings.title": "PcapLens - Settings",
        "settings.caption": "Tune parser behavior and display limits for the current session.",
        "settings.language": "Language",
        "settings.language_select": "UI language",
        "settings.parser": "Parser",
        "settings.backend_selected": "{label} selected",
        "settings.tshark_unavailable": (
            "tshark is not available on PATH, so that option is disabled."
        ),
        "settings.display": "Display",
        "settings.packet_table_rows": "Packet table rows",
        "settings.top_n": "Top-N charts and summaries",
        "settings.cache": "Cache",
        "settings.clear_parse_cache": "Clear parse cache",
        "settings.parse_cache_cleared": "Parse cache cleared.",
        "settings.environment": "Environment",
        "settings.available": "available",
        "settings.unavailable": "unavailable",
        "settings.unknown": "unknown",
        "sections.loaded": "Loaded **{filename}** ({size_mb:.2f} MB)",
        "sections.parser_backend": "Parser backend: `{backend}`",
        "sections.filters": "Filters",
        "sections.no_packets_filter": "No packets to filter.",
        "sections.protocol": "Protocol",
        "sections.src_ip_contains": "Source IP contains",
        "sections.dst_ip_contains": "Destination IP contains",
        "sections.showing_packets": "Showing {filtered:,} of {total:,} packets",
        "sections.parse_warning": "{count} packet(s) could not be parsed and were skipped.",
        "sections.traffic_summary": "Traffic Summary",
        "sections.total_packets": "Total Packets",
        "sections.total_bytes": "Total Bytes",
        "sections.duration": "Duration",
        "sections.unique_src_ips": "Unique Source IPs",
        "sections.unique_dst_ips": "Unique Destination IPs",
        "sections.insights": "Insights",
        "sections.severity": "Severity: `{severity}`",
        "severity.info": "info",
        "severity.notice": "notice",
        "severity.warning": "warning",
        "insight.no_packets.title": "No packets to inspect",
        "insight.no_packets.evidence": "The current view contains 0 packets.",
        "insight.no_packets.action": (
            "Upload a capture, start live capture, or loosen active filters."
        ),
        "insight.no_notable_patterns.title": "No notable traffic patterns detected",
        "insight.no_notable_patterns.evidence": (
            "Reviewed {total_packets:,} packets with current rules."
        ),
        "insight.no_notable_patterns.action": (
            "Use filters or inspect the packet table for protocol-specific details."
        ),
        "insight.top_talker.title": "One source dominates the capture",
        "insight.top_talker.evidence": ("{ip} sent {count:,} packets ({share:.1f}% of this view)."),
        "insight.top_talker.action": (
            "Filter source IP contains {ip} and inspect destinations and ports."
        ),
        "insight.inbound_to_local.title": "Most captured traffic is inbound to this host",
        "insight.inbound_to_local.evidence": (
            "{ip} appears to be local and received {count:,} packets "
            "({share:.1f}% of this view)."
        ),
        "insight.inbound_to_local.action": (
            "Review top source IPs and destination ports to understand inbound services."
        ),
        "insight.top_destination.title": "Traffic concentrates on one destination",
        "insight.top_destination.evidence": (
            "{ip} received {count:,} packets ({share:.1f}% of this view)."
        ),
        "insight.top_destination.action": (
            "Filter destination IP contains {ip} and review protocols involved."
        ),
        "insight.dns_activity.title": "DNS queries are present",
        "insight.dns_activity.evidence": ("Top DNS query is {query} with {count:,} occurrence(s)."),
        "insight.dns_activity.action": (
            "Review repeated DNS lookups for {query}; UDP packets in view: {dns_count:,}."
        ),
        "insight.http_activity.title": "HTTP request traffic detected",
        "insight.http_activity.evidence": "Top HTTP host is {host_text}.{methods_text}",
        "insight.http_activity.methods": " Methods: {methods}.",
        "insight.http_activity.action": (
            "Inspect HTTP hosts and methods before sharing captures externally."
        ),
        "insight.tcp_resets.title": "TCP resets observed",
        "insight.tcp_resets.evidence": (
            "RST appeared {resets:,} time(s), about {share:.1f}% of TCP packets."
        ),
        "insight.tcp_resets.action": (
            "Check whether resets align with failed connections, blocked ports, "
            "or service restarts."
        ),
        "insight.high_port_activity.title": "High destination port activity",
        "insight.high_port_activity.evidence": (
            "Port {port} appears {count:,} time(s) among top destination ports."
        ),
        "insight.high_port_activity.action": (
            "Confirm whether this is expected ephemeral-port or application-specific traffic."
        ),
        "sections.charts": "Charts",
        "sections.dns_http": "DNS / HTTP",
        "sections.no_dns_http": "No DNS or HTTP traffic detected in this capture.",
        "sections.top_dns_queries": "Top DNS Queries",
        "sections.no_dns_queries": "No DNS queries.",
        "sections.top_http_hosts": "Top HTTP Hosts",
        "sections.no_http_hosts": "No HTTP hosts.",
        "sections.http_methods": "HTTP methods - {methods}",
        "sections.packet_table": "Packet Table (first {row_limit} rows)",
        "sections.no_packets_display": "No packets to display.",
        "sections.export": "Export",
        "sections.nothing_to_export": "Nothing to export.",
        "sections.export_all": "Export all {count:,} filtered packets.",
        "sections.download_csv": "Download CSV",
        "sections.download_json": "Download JSON",
        "sections.metrics_comparison": "Metrics Comparison",
        "sections.comparison_charts": "Comparison Charts",
        "charts.no_protocol_data": "No protocol data",
        "charts.protocol": "Protocol",
        "charts.packet_count": "Packet Count",
        "charts.protocol_distribution": "Protocol Distribution",
        "charts.no_source_ip_data": "No source IP data",
        "charts.source_ip": "Source IP",
        "charts.top_source_ips": "Top Source IPs",
        "charts.no_destination_port_data": "No destination port data",
        "charts.destination_port": "Destination Port",
        "charts.top_destination_ports": "Top Destination Ports",
        "charts.no_tcp_flag_data": "No TCP flag data",
        "charts.tcp_flag": "TCP Flag",
        "charts.count": "Count",
        "charts.tcp_flags_distribution": "TCP Flags Distribution",
        "charts.no_traffic_data": "No traffic data",
        "charts.time": "Time",
        "charts.traffic_over_time": "Traffic Over Time",
        "charts.file": "File",
        "charts.protocol_distribution_by_file": "Protocol Distribution by File",
        "charts.seconds_since_start": "Seconds since capture start",
        "charts.traffic_over_time_by_file": "Traffic Over Time by File",
    },
    "zh-TW": {
        "app.analyze": "分析",
        "app.compare": "比較",
        "app.live": "即時擷取",
        "app.settings": "設定",
        "analyze.title": "PcapLens - 分析",
        "analyze.caption": "上傳 .pcap 檔案，立即取得流量摘要與圖表。",
        "analyze.upload_label": "選擇 .pcap 檔案",
        "analyze.upload_prompt": "上傳 .pcap 檔案以開始分析。",
        "analyze.parse_error": "無法解析檔案：{error}",
        "compare.title": "PcapLens - 比較",
        "compare.caption": "上傳兩個以上的 .pcap 檔案，並排比較流量。",
        "compare.upload_label": "選擇 .pcap 檔案",
        "compare.upload_prompt": "請上傳至少兩個 .pcap 檔案進行比較。",
        "compare.file_parse_error": "{name}：無法解析 - {error}",
        "compare.backend_caption": "{name} 解析器後端：`{backend}`",
        "compare.skipped_packets": "{name}：解析時略過 {count} 個封包。",
        "compare.need_two_files": "需要至少兩個有效的 .pcap 檔案才能比較。",
        "live.title": "PcapLens - 即時擷取",
        "live.caption": "使用 tshark 或 Scapy 擷取即時流量，並在封包抵達時檢視結果。",
        "live.interface": "網路介面",
        "live.rolling_packets": "保留封包數",
        "live.actual_backend": "實際後端：`{backend}`",
        "live.capture_filter": "擷取篩選器",
        "live.auto_refresh": "自動重新整理",
        "live.start": "開始",
        "live.stop": "停止",
        "live.clear": "清除",
        "live.no_interfaces": "找不到 {backend} 可用的擷取介面。",
        "live.auto_refresh_off": "自動重新整理已關閉；請使用 Streamlit 重新執行控制來更新封包。",
        "live.tshark_unavailable": "tshark 無法使用；Auto 會改用 Scapy。",
        "live.interface_error": "無法列出擷取介面：{error}",
        "live.status": "狀態：`{status}`",
        "live.status_capturing": "擷取中",
        "live.status_stopped": "已停止",
        "live.interface_caption": "網路介面：`{interface}`",
        "live.capture_filter_caption": "擷取篩選器：`{capture_filter}`",
        "live.parse_warning": "{count} 行即時封包資料無法解析。",
        "live.capture_messages": "擷取訊息",
        "live.buffered_packets": "緩衝封包數",
        "live.download_pcap": "下載 PCAP",
        "settings.title": "PcapLens - 設定",
        "settings.caption": "調整目前工作階段的解析器行為與顯示限制。",
        "settings.language": "語言",
        "settings.language_select": "介面語言",
        "settings.parser": "解析器",
        "settings.backend_selected": "{label} 已選取",
        "settings.tshark_unavailable": "PATH 中找不到 tshark，因此此選項已停用。",
        "settings.display": "顯示",
        "settings.packet_table_rows": "封包表格列數",
        "settings.top_n": "Top-N 圖表與摘要",
        "settings.cache": "快取",
        "settings.clear_parse_cache": "清除解析快取",
        "settings.parse_cache_cleared": "解析快取已清除。",
        "settings.environment": "環境",
        "settings.available": "可用",
        "settings.unavailable": "不可用",
        "settings.unknown": "未知",
        "sections.loaded": "已載入 **{filename}**（{size_mb:.2f} MB）",
        "sections.parser_backend": "解析器後端：`{backend}`",
        "sections.filters": "篩選器",
        "sections.no_packets_filter": "沒有可篩選的封包。",
        "sections.protocol": "協定",
        "sections.src_ip_contains": "來源 IP 包含",
        "sections.dst_ip_contains": "目的 IP 包含",
        "sections.showing_packets": "顯示 {filtered:,} / {total:,} 個封包",
        "sections.parse_warning": "{count} 個封包無法解析並已略過。",
        "sections.traffic_summary": "流量摘要",
        "sections.total_packets": "封包總數",
        "sections.total_bytes": "位元組總數",
        "sections.duration": "期間",
        "sections.unique_src_ips": "唯一來源 IP 數",
        "sections.unique_dst_ips": "唯一目的 IP 數",
        "sections.insights": "洞察",
        "sections.severity": "嚴重度：`{severity}`",
        "severity.info": "資訊",
        "severity.notice": "注意",
        "severity.warning": "警告",
        "insight.no_packets.title": "沒有可檢查的封包",
        "insight.no_packets.evidence": "目前檢視包含 0 個封包。",
        "insight.no_packets.action": "請上傳擷取檔、開始即時擷取，或放寬目前篩選條件。",
        "insight.no_notable_patterns.title": "未偵測到明顯的流量模式",
        "insight.no_notable_patterns.evidence": ("已使用目前規則檢查 {total_packets:,} 個封包。"),
        "insight.no_notable_patterns.action": "可使用篩選器或封包表格查看特定協定細節。",
        "insight.top_talker.title": "單一來源主導此擷取",
        "insight.top_talker.evidence": "{ip} 傳送 {count:,} 個封包（此檢視的 {share:.1f}%）。",
        "insight.top_talker.action": "以來源 IP 包含 {ip} 篩選，並檢查目的地與連接埠。",
        "insight.inbound_to_local.title": "多數擷取流量流入此主機",
        "insight.inbound_to_local.evidence": (
            "{ip} 看起來是本機位址，並接收 {count:,} 個封包" "（此檢視的 {share:.1f}%）。"
        ),
        "insight.inbound_to_local.action": "檢查主要來源 IP 與目的連接埠，以了解入站服務。",
        "insight.top_destination.title": "流量集中在單一目的地",
        "insight.top_destination.evidence": (
            "{ip} 接收 {count:,} 個封包（此檢視的 {share:.1f}%）。"
        ),
        "insight.top_destination.action": "以目的 IP 包含 {ip} 篩選，並檢查相關協定。",
        "insight.dns_activity.title": "偵測到 DNS 查詢",
        "insight.dns_activity.evidence": "主要 DNS 查詢是 {query}，出現 {count:,} 次。",
        "insight.dns_activity.action": (
            "檢查 {query} 的重複 DNS 查詢；目前檢視中的 UDP 封包：{dns_count:,}。"
        ),
        "insight.http_activity.title": "偵測到 HTTP 請求流量",
        "insight.http_activity.evidence": "主要 HTTP 主機是 {host_text}。{methods_text}",
        "insight.http_activity.methods": " 方法：{methods}。",
        "insight.http_activity.action": "對外分享擷取檔前，請檢查 HTTP 主機與方法。",
        "insight.tcp_resets.title": "觀察到 TCP reset",
        "insight.tcp_resets.evidence": ("RST 出現 {resets:,} 次，約占 TCP 封包的 {share:.1f}%。"),
        "insight.tcp_resets.action": "檢查 reset 是否與連線失敗、連接埠封鎖或服務重啟有關。",
        "insight.high_port_activity.title": "高位目的連接埠活動",
        "insight.high_port_activity.evidence": (
            "連接埠 {port} 在主要目的連接埠中出現 {count:,} 次。"
        ),
        "insight.high_port_activity.action": (
            "確認這是否為預期的 ephemeral port 或應用程式特定流量。"
        ),
        "sections.charts": "圖表",
        "sections.dns_http": "DNS / HTTP",
        "sections.no_dns_http": "此擷取中未偵測到 DNS 或 HTTP 流量。",
        "sections.top_dns_queries": "主要 DNS 查詢",
        "sections.no_dns_queries": "沒有 DNS 查詢。",
        "sections.top_http_hosts": "主要 HTTP 主機",
        "sections.no_http_hosts": "沒有 HTTP 主機。",
        "sections.http_methods": "HTTP 方法 - {methods}",
        "sections.packet_table": "封包表格（前 {row_limit} 列）",
        "sections.no_packets_display": "沒有可顯示的封包。",
        "sections.export": "匯出",
        "sections.nothing_to_export": "沒有可匯出的資料。",
        "sections.export_all": "匯出全部 {count:,} 個已篩選封包。",
        "sections.download_csv": "下載 CSV",
        "sections.download_json": "下載 JSON",
        "sections.metrics_comparison": "指標比較",
        "sections.comparison_charts": "比較圖表",
        "charts.no_protocol_data": "沒有協定資料",
        "charts.protocol": "協定",
        "charts.packet_count": "封包數",
        "charts.protocol_distribution": "協定分布",
        "charts.no_source_ip_data": "沒有來源 IP 資料",
        "charts.source_ip": "來源 IP",
        "charts.top_source_ips": "主要來源 IP",
        "charts.no_destination_port_data": "沒有目的連接埠資料",
        "charts.destination_port": "目的連接埠",
        "charts.top_destination_ports": "主要目的連接埠",
        "charts.no_tcp_flag_data": "沒有 TCP 旗標資料",
        "charts.tcp_flag": "TCP 旗標",
        "charts.count": "數量",
        "charts.tcp_flags_distribution": "TCP 旗標分布",
        "charts.no_traffic_data": "沒有流量資料",
        "charts.time": "時間",
        "charts.traffic_over_time": "流量時間序列",
        "charts.file": "檔案",
        "charts.protocol_distribution_by_file": "各檔案協定分布",
        "charts.seconds_since_start": "擷取開始後秒數",
        "charts.traffic_over_time_by_file": "各檔案流量時間序列",
    },
}


def init_language() -> None:
    st.session_state.setdefault(LANGUAGE_KEY, DEFAULT_LANGUAGE)


def get_language() -> str:
    init_language()
    return st.session_state[LANGUAGE_KEY]


def t(key: str, **kwargs) -> str:
    language = get_language()
    text = TRANSLATIONS.get(language, {}).get(key)
    if text is None:
        text = TRANSLATIONS[DEFAULT_LANGUAGE].get(key, key)
    return text.format(**kwargs)
