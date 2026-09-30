# Network Intrusion Detection Lab — SOC Dashboard

A controlled cybersecurity laboratory project demonstrating network reconnaissance, traffic analysis, IDS detection, alert generation, and security-event visualization.

> **Authorized and Isolated Lab** — All attack activity takes place inside a VirtualBox host-only network. No external systems are targeted or compromised.

---

## Real-World NIDS/SOC Context

This project simulates a small-enterprise Security Operations Center (SOC) monitoring workflow. The full detection pipeline is:

```
Kali Linux          Metasploitable2       Network Traffic
(Attacker)    --->  (Victim Server)  --->  192.168.56.0/24
                                                |
                                           Wireshark
                                          (Capture .pcap)
                                                |
                                           Suricata IDS
                                          (eve.json alerts)
                                                |
                                       Flask SOC Dashboard
                                        (Parse + Visualize)
```

The project does **not** claim to invent a new IDS. Its contribution is the practical integration of:
- Controlled attack generation (Kali + nmap + Metasploit)
- Passive traffic capture (Wireshark)
- Rule-based intrusion detection (Suricata)
- Alert parsing and normalisation (Python)
- SOC-style security analytics dashboard (Flask + Chart.js)

---

## Team

| Name | Role |
|------|------|
| **Devansh Chaubey** (Leader) | Attack / Reconnaissance Module + Project Integration |
| Divija Srivastava | Suricata IDS / Detection Module |
| Manya | Metasploitable2 Victim Environment + Wireshark / Traffic Analysis |
| Anshika Srivastava | Flask / Python Dashboard and Visualization |
| Sharat Chodhary | Integration and Testing |

---

## Features

- **Main Dashboard** — Stat cards (total, critical, high, medium, low, today, unique IPs), alert timeline chart, protocol distribution, attack categories, top source/destination IPs, top destination ports, and recent alerts
- **Alert Investigation** — Full-featured table with search, multi-filter (severity, category, protocol, source IP, destination IP), column sorting, and pagination
- **Alert Detail Modal** — All Suricata fields: timestamp, signature, SID, GID, severity, category, source/destination IP/port, protocol, flow ID, action, plus raw Suricata JSON
- **Traffic Analysis** — Source→destination flow pairs, protocol breakdown, top talkers, source/destination port charts. All derived from alert data (no invented metrics)
- **PCAP Analysis** — Secure file upload (.pcap/.pcapng), offline analysis workflow documentation, uploaded file list
- **Detection Rules** — SID, signature, category, severity, protocol, enabled/disabled state. Demo ruleset shown when no real rules file is configured
- **System Status** — Truthful status for all components (ONLINE, OFFLINE, SIMULATION MODE, UNKNOWN, OFFLINE WORKFLOW). Never fakes live connectivity
- **Project / About** — Architecture flow, technology stack, team members, and lab disclaimer

---

## Technology Stack

| Layer | Technology |
|-------|-----------|
| Backend | Python 3.x + Flask |
| Frontend | HTML5, Vanilla CSS (Glassmorphism), Vanilla JavaScript |
| Charts | Chart.js (CDN) |
| Icons | Inline SVG |
| Storage | JSON file (eve.json) — no database required |
| Testing | pytest |

---

## Project Structure

```
DASHBOARD/
├── app.py                    # Flask application entry point
├── config.py                 # Configuration (reads .env)
├── requirements.txt          # Python dependencies
├── .env.example              # Environment variable template
├── generate_demo_data.py     # Demo data generator
│
├── backend/
│   ├── __init__.py
│   ├── parser.py             # Suricata eve.json parser
│   ├── store.py              # In-memory data store + query helpers
│   ├── routes.py             # Flask API blueprints
│   ├── pcap_handler.py       # Secure PCAP upload handler
│   └── rules.py              # Suricata rules file reader
│
├── frontend/
│   ├── templates/
│   │   └── index.html        # Single-page app template
│   └── static/
│       ├── css/style.css     # Glassmorphism design system
│       └── js/app.js         # SPA routing + all section logic
│
├── data/
│   ├── demo/
│   │   └── sample_eve.json   # Bundled realistic demo dataset
│   └── uploads/              # Uploaded PCAP files (auto-created)
│
└── tests/
    ├── __init__.py
    ├── test_app.py           # 38 automated tests (pytest)
    └── verify_api.py         # Live API verification script
```

---

## Installation

### Prerequisites
- Python 3.10 or later
- Internet access (to download Chart.js from CDN when viewing the dashboard)

### Steps

```bash
# 1. Clone / navigate to the project directory
cd "PROJECT EXHIBITION 1/DASHBOARD"

# 2. Create and activate a virtual environment
python -m venv venv

# Windows:
.\venv\Scripts\activate

# Linux / macOS:
source venv/bin/activate

# 3. Install dependencies
pip install -r requirements.txt

# 4. (Optional) Regenerate the demo dataset
python generate_demo_data.py

# 5. Configure environment
cp .env.example .env
# Edit .env if needed (defaults work for demo mode)
```

---

## Running the Application

```bash
# Make sure the virtual environment is activated first

python app.py
```

Open your browser at: **http://127.0.0.1:5000**

The dashboard starts in **DEMO / SIMULATION MODE** by default, loading the bundled realistic dataset. The UI clearly labels this as demo data.

---

## Configuration

Copy `.env.example` to `.env` and edit as needed:

```env
DATA_MODE=demo          # "demo" or "suricata"
FLASK_HOST=127.0.0.1
FLASK_PORT=5000
FLASK_DEBUG=false
```

---

## Data Modes

### DEMO / SIMULATION Mode (default)

```env
DATA_MODE=demo
```

- Uses `data/demo/sample_eve.json` (172 events including 170 alerts with varied severities, categories, and attack types)
- Includes realistic Nmap scan alerts, exploitation attempts, DoS events, and malware detection events
- All using the lab IP range: 192.168.56.0/24
- Always clearly labelled **SIMULATION MODE** in the UI

### Real Suricata Mode

```env
DATA_MODE=suricata
SURICATA_EVE_PATH=/var/log/suricata/eve.json
```

- Reads a real `eve.json` produced by Suricata
- If the file is missing or unreadable, the dashboard shows an informative state instead of crashing
- The UI labels data as **LIVE DATA** when a real file is loaded

---

## Connecting to Real Suricata

### 1. Run Suricata in live mode (on the Suricata machine)

```bash
sudo suricata -c /etc/suricata/suricata.yaml -i eth0
# Alerts are written to /var/log/suricata/eve.json
```

### 2. Point the dashboard at the eve.json

```env
DATA_MODE=suricata
SURICATA_EVE_PATH=/var/log/suricata/eve.json
```

### 3. Restart the dashboard

```bash
python app.py
```

The dashboard reads the file at startup. To refresh, click the **Refresh** button in the top bar (reloads from disk) or restart the app.

---

## Offline PCAP Workflow

This is the workflow for analysing a captured PCAP file:

```
1. Capture traffic with Wireshark → File > Export as capture.pcap
2. Upload the .pcap file in the dashboard (PCAP section)
3. Run Suricata offline against the PCAP:
   suricata -r capture.pcap -c /etc/suricata/suricata.yaml -l /var/log/suricata/
4. Copy the resulting eve.json to the configured path
5. Set DATA_MODE=suricata and SURICATA_EVE_PATH accordingly
6. Restart the dashboard
```

> **Important:** Uploading a PCAP to the dashboard does NOT automatically run Suricata. This is an offline workflow. The dashboard stores the PCAP file and provides instructions for the offline analysis step.

---

## Reconnaissance Commands Used in the Lab

These are the Nmap commands run from Kali Linux. When Suricata detects them, the alerts appear in the dashboard:

```bash
# Host discovery
nmap -sn 192.168.56.0/24

# SYN scan (stealthy)
nmap -sS 192.168.56.110

# Service and version detection
nmap -sV 192.168.56.110

# OS fingerprinting
nmap -O 192.168.56.110

# Aggressive scan (OS + version + scripts + traceroute)
nmap -A 192.168.56.110

# Vulnerability scripts
sudo nmap --script vuln 192.168.56.110
```

---

## Running Tests

```bash
# Run the full automated test suite (38 tests)
.\venv\Scripts\python -m pytest tests/test_app.py -v

# Verify live API endpoints (Flask must be running)
.\venv\Scripts\python tests\verify_api.py
```

---

## API Endpoints

| Endpoint | Description |
|----------|-------------|
| `GET /api/health` | Health check |
| `GET /api/stats` | Summary statistics |
| `GET /api/alerts` | Paginated, filtered, sorted alerts |
| `GET /api/alerts/<id>` | Single alert detail |
| `GET /api/timeline` | Alert counts by time bucket |
| `GET /api/top-sources` | Top source IPs |
| `GET /api/top-destinations` | Top destination IPs |
| `GET /api/protocols` | Protocol distribution |
| `GET /api/categories` | Alert categories |
| `GET /api/top-dest-ports` | Top destination ports |
| `GET /api/flow-pairs` | Source→destination pairs |
| `GET /api/filter-options` | Available filter values |
| `GET /api/rules` | Detection rules |
| `GET /api/system-status` | Component status |
| `GET /api/pcap/list` | Uploaded PCAP files |
| `POST /api/pcap/upload` | Upload a PCAP file |

### Alert filter parameters

`/api/alerts?search=Nmap&severity=critical&category=...&protocol=TCP&src_ip=192.168.56.101&dest_ip=...&sort_by=timestamp&sort_order=desc&page=1&per_page=25`

---

## Troubleshooting

| Problem | Solution |
|---------|----------|
| `ModuleNotFoundError: flask` | Activate the venv first: `.\venv\Scripts\activate` |
| Port 5000 already in use | Set `FLASK_PORT=5001` in `.env` |
| Demo data not loading | Run `python generate_demo_data.py` to regenerate |
| Charts not rendering | Check browser console; ensure internet access for Chart.js CDN |
| Suricata eve.json not loading | Check `SURICATA_EVE_PATH` in `.env`; check file permissions |
| `DATA_MODE=suricata` shows no data | Check the eve.json path and that Suricata has written alert events |

---

## Limitations

1. **No live streaming** — The dashboard reads `eve.json` at startup. It does not tail the file in real-time. Refresh or restart to see new alerts.
2. **In-memory only** — All alert data is stored in memory. For very large eve.json files (millions of events), consider SQLite or adding a pagination limit at the parser level.
3. **No authentication** — This is a local lab dashboard. Do not expose it to the internet without adding authentication.
4. **Traffic metrics are alert-derived** — Packet counts, bandwidth, and total traffic volume are not available from Suricata alert events alone. The traffic section only shows what can be honestly derived from the alert data.
5. **PCAP upload does not trigger Suricata** — This is an intentional design decision for security. The offline workflow is documented clearly in the UI and in this README.
6. **No automatic file reload** — Click the Refresh button or restart the server to pick up new alerts from eve.json.

---

## Future Improvements

- File-tail mode: watch `eve.json` for new lines and update the dashboard without restart
- SQLite backend: for persistent storage of large alert volumes
- User authentication: basic login before accessing the dashboard
- Alert acknowledgement: mark alerts as reviewed/investigated
- Custom rule upload: allow uploading `.rules` files through the UI
- Suricata process management: safely trigger offline PCAP analysis within the dashboard (with strict sandboxing)
- Export to CSV/PDF: download alert tables for reporting

---

## Security Notes

- PCAP uploads are validated (extension, size, path traversal prevention)
- All alert data rendered in the UI is HTML-escaped
- No shell execution of arbitrary commands
- No external network calls from the backend (Chart.js loads from CDN in the browser only)
- `SECRET_KEY` should be changed from the default in any non-local deployment

---

*Built for college exhibition — authorized, isolated, educational cybersecurity laboratory.*
