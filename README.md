# PcapLens

A lightweight Python tool that lets you upload a `.pcap` file and instantly get traffic summaries and interactive charts.

---

## Features

- Upload `.pcap` files via a browser UI
- Traffic summary: packet count, total bytes, duration, unique IPs
- Charts: protocol distribution, top source IPs, top destination ports,
  TCP flags distribution, traffic over time
- DNS / HTTP summary: top DNS queries, top HTTP hosts, HTTP method breakdown
- Packet table (first 100 rows)
- Sidebar filters: by protocol and by source / destination IP
- Export filtered packets to CSV or JSON
- Multi-file comparison: metrics table and overlaid charts across captures
- Live capture mode powered by `tshark` or Scapy
- Download stopped live captures as `.pcap`
- Explainable traffic insights with severity, evidence, and suggested action
- English / Traditional Chinese UI language selection
- Parse-once caching — fast re-renders after initial load

---

## Tech Stack

| Layer      | Library     |
|------------|-------------|
| UI         | Streamlit   |
| PCAP parse | Scapy       |
| Data       | Polars      |
| Charts     | Plotly      |
| Tests      | Pytest      |
| Lint/fmt   | Ruff, Black |

---

## Installation

```bash
git clone https://github.com/your-username/pcap-lens.git
cd pcap-lens

python3 -m venv .venv
source .venv/bin/activate       # Windows: .venv\Scripts\activate

pip install -r requirements.txt
```

---

## Usage

```bash
uv run streamlit run app.py
# OR 
streamlit run app.py
```

Then open `http://localhost:8501` in your browser and upload a `.pcap` file.

A sample file is provided at `sample_data/demo.pcap` to try it out immediately.

---

## Project Structure

```
pcap-lens/
├─ app.py                  # Streamlit entry point — navigation router
├─ src/
│  ├─ config.py            # Centralised settings
│  ├─ domain/models.py     # PacketRecord dataclass
│  ├─ ingest/upload.py     # File validation
│  ├─ parser/pcap_parser.py
│  ├─ capture/
│  │  └─ live_capture.py # tshark / Scapy live capture backends
│  ├─ transform/
│  │  ├─ packet_table.py   # records -> Polars DataFrame
│  │  └─ filters.py        # protocol / IP filters
│  ├─ analysis/
│  │  ├─ summary.py        # Traffic statistics
│  │  ├─ charts.py         # Plotly figures
│  │  ├─ export.py         # CSV / JSON serialization
│  │  └─ compare.py        # Multi-file comparison tables
│  └─ ui/
│     ├─ sections.py       # Page sections
│     ├─ pages.py          # Analyze / Compare pages + cache
│     ├─ live.py           # Live capture page
│     └─ settings.py       # Session settings page
├─ tests/
│  ├─ conftest.py
│  ├─ test_parser.py     # incl. DNS / HTTP extraction
│  ├─ test_summary.py
│  ├─ test_charts.py
│  ├─ test_filters.py
│  ├─ test_export.py
│  └─ test_compare.py
├─ sample_data/demo.pcap
├─ requirements.txt
└─ pyproject.toml
```

The app has two pages, switchable from the sidebar:

- **Analyze** — single-file analysis: filters, summary, charts, packet table, export
- **Compare** — upload two or more `.pcap` files and compare metrics and charts side by side
- **Live** — capture from a local interface with `tshark` or Scapy and inspect rolling traffic
- **Settings** — choose UI language, parser backend, display limits, cache controls, environment status

---

## Running Tests

```bash
pytest
```

---

## Roadmap

**v0.2** ✓ complete
- [x] Protocol / IP filter
- [x] Export to CSV / JSON
- [x] Top destination ports
- [x] TCP flags statistics

**v0.3** ✓ complete
- [x] DNS / HTTP basic summary
- [x] Multi-file comparison

**v0.3.1** ✓ complete
- [x] Add a `tshark -T fields` + Polars parsing backend, used automatically when
      `tshark` is on PATH; falls back to the existing Scapy parser otherwise
      (faster parsing with no new hard dependency — Scapy stays as the fallback)
- [x] Add Settings page for parser backend selection, display limits, cache
      clearing, and environment status

**v0.4** ✓ complete
- [x] Add tshark-only Live Capture page
- [x] Detect available capture interfaces via `tshark -D`
- [x] Start / stop `tshark` live capture subprocess
- [x] Support optional capture filter
- [x] Parse live `tshark -T fields` output into packet records
- [x] Show realtime backend/status marker
- [x] Render live summary, charts, and packet table
- [x] Add rolling packet buffer limit
- [x] Handle permissions and tshark unavailable states gracefully

**v0.4.1** ✓ complete
- [x] Add Scapy live capture backend
- [x] Add Live backend selector: Auto / tshark / Scapy
- [x] Auto-select tshark first, then Scapy when tshark is unavailable
- [x] List Scapy capture interfaces
- [x] Reuse Scapy packet parsing for live packets
- [x] Drain Scapy live packets through a background queue

**v0.4.2** ✓ complete
- [x] Save tshark live captures with `-w`
- [x] Save Scapy live captures from buffered raw packets
- [x] Provide Download PCAP after stopping a live capture
- [x] Clean up temporary tshark capture files

**v0.5** ✓ complete
- [x] Add Insights section
- [x] Generate deterministic traffic observations
- [x] Show severity, evidence, and suggested next action
- [x] Apply insights to Analyze and Live pages
- [x] Make destination concentration insights local-IP aware
- [x] Add tests for insight rules

**v0.5.1** ✓ complete
- [x] Add language preference in Settings
- [x] Support English and Traditional Chinese UI labels
- [x] Add translation helper with English fallback
- [x] Apply translations to navigation, Analyze, Compare, Live, Settings, and chart labels

**v0.6** — planned
- [ ] Add professional HTML / Markdown report export
- [ ] Include summary, charts, insights, and packet samples

**Future**
- REST API
- Suspicious traffic hints
