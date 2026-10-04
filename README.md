# Network Intrusion Detection Lab (NIDS Lab)

A small-scale simulation of a **passive Enterprise Network Intrusion Detection System (NIDS)** operating as part of a **Security Operations Center (SOC)** monitoring workflow.

The project demonstrates an end-to-end cybersecurity monitoring pipeline in an isolated virtual laboratory:

**Controlled Attack → Network Traffic → Suricata NIDS → eve.json → Flask Backend → SOC-Style Dashboard**

The lab uses Kali Linux as the simulated attacker and monitoring host, Metasploitable2 as the intentionally vulnerable victim, Suricata as the passive NIDS sensor, and a Python/Flask dashboard for alert visualization.

> **Important:** This project is an educational simulation. It is not a production enterprise SOC, IPS, SIEM, or automated prevention system.

---

# Table of Contents

1. [Project Overview](#project-overview)
2. [Project Objective](#project-objective)
3. [Real-World Concept](#real-world-concept)
4. [Architecture](#architecture)
5. [Data Flow](#data-flow)
6. [Component Roles](#component-roles)
7. [Technology Stack](#technology-stack)
8. [Lab Network Configuration](#lab-network-configuration)
9. [Detection Rules](#detection-rules)
10. [Quick Demo Runbook](#quick-demo-runbook)
11. [Complete Setup](#complete-setup)
12. [Suricata Configuration](#suricata-configuration)
13. [Flask Dashboard Setup](#flask-dashboard-setup)
14. [Attack and Detection Testing](#attack-and-detection-testing)
15. [API Reference](#api-reference)
16. [Live Dashboard Behavior](#live-dashboard-behavior)
17. [Validation and Testing](#validation-and-testing)
18. [Repository Structure](#repository-structure)
19. [Troubleshooting](#troubleshooting)
20. [Final Presentation Checklist](#final-presentation-checklist)
21. [Post-Demo Cleanup](#post-demo-cleanup)
22. [Limitations](#limitations)
23. [Future Improvements](#future-improvements)
24. [Learning Outcomes](#learning-outcomes)
25. [Team Responsibilities](#team-responsibilities)
26. [Security and Ethical Use](#security-and-ethical-use)

---

# Project Overview

The **Network Intrusion Detection Lab** is a controlled virtual cybersecurity laboratory designed to demonstrate how a basic passive NIDS workflow operates.

The project simulates the following environment:

```text
                    Controlled Attack Traffic
                             |
                             v
                    +----------------+
                    |   Kali Linux   |
                    |    Attacker    |
                    | Nmap / Hydra   |
                    +-------+--------+
                            |
                            | Host-Only Network
                            | 192.168.56.0/24
                            v
                  +-----------------------+
                  |    Metasploitable2    |
                  |  Intentionally         |
                  |  Vulnerable Victim     |
                  +-----------+-----------+
                              |
                              | Network Traffic
                              v
                  +-----------------------+
                  |   Suricata 8.0.7      |
                  |   Passive NIDS Sensor  |
                  +-----------+-----------+
                              |
                              | Alert Events
                              v
                  +-----------------------+
                  |      eve.json          |
                  | /var/log/suricata/     |
                  +-----------+-----------+
                              |
                              | Parsed by Flask
                              v
                  +-----------------------+
                  |    Flask Backend       |
                  | Python REST API        |
                  +-----------+-----------+
                              |
                              | HTTP / JSON
                              v
                  +-----------------------+
                  | SOC-Style Dashboard    |
                  | Near-real-time polling |
                  +-----------------------+
```

---

# Project Objective

The main objectives of the project are:

* Simulate a small enterprise-style network monitoring environment.
* Generate controlled reconnaissance and brute-force traffic.
* Detect suspicious traffic using Suricata.
* Generate structured alert records through `eve.json`.
* Parse Suricata alerts using a Python backend.
* Expose alert information through REST APIs.
* Display alerts and network information through a SOC-style dashboard.
* Demonstrate near-real-time dashboard updates.
* Provide a reproducible cybersecurity laboratory for academic evaluation.

---

# Real-World Concept

The project represents a simplified version of a **Network Intrusion Detection System (NIDS)** used in security monitoring environments.

In a real organization:

```text
Network Traffic
       |
       v
NIDS Sensor
       |
       v
Detection Rules
       |
       v
Security Events
       |
       v
SOC / SIEM
       |
       v
Security Analyst
```

Our project implements a smaller version of this workflow:

```text
Kali Attack Traffic
       |
       v
Suricata NIDS
       |
       v
eve.json
       |
       v
Flask Backend
       |
       v
SOC-Style Dashboard
```

### What the project IS

* Passive NIDS simulation
* Controlled network monitoring laboratory
* Signature-based detection demonstration
* Suricata-based alert generation
* Flask-based monitoring dashboard
* SOC-style visualization

### What the project IS NOT

* IPS
* Packet-blocking system
* Production enterprise SOC
* SIEM replacement
* AI/ML detection engine
* Automated response system
* Full enterprise NDR platform

---

# Architecture

```text
                         WINDOWS HOST
                    Browser / Project Demo
                              |
                              | HTTP
                              v
+------------------------------------------------------------------+
|                         KALI LINUX VM                            |
|                         192.168.56.101                           |
|                                                                  |
|  +----------------+       +----------------------+               |
|  | Nmap / Hydra   | ----> | eth1 Host-Only       |               |
|  | Simulated      |       | Interface            |               |
|  | Attacker       |       +----------+-----------+               |
|  +----------------+                  |                           |
|                                      |                           |
|                                      v                           |
|                           +--------------------+                 |
|                           | Suricata 8.0.7     |                 |
|                           | Passive NIDS       |                 |
|                           +---------+----------+                 |
|                                     |                            |
|                                     v                            |
|                           /var/log/suricata/                     |
|                                  eve.json                        |
|                                     |                            |
|                                     v                            |
|                           +--------------------+                 |
|                           | Flask Backend      |                 |
|                           | parser/store/API   |                 |
|                           +---------+----------+                 |
|                                     |                            |
|                                     v                            |
|                           +--------------------+                 |
|                           | Web Dashboard      |                 |
|                           | SOC-style UI       |                 |
|                           +--------------------+                 |
|                                                                  |
+------------------------------+-----------------------------------+
                               |
                               | Host-Only Network
                               | 192.168.56.0/24
                               v
                    +-------------------------+
                    |    Metasploitable2      |
                    |    192.168.56.102        |
                    |    Vulnerable Victim    |
                    +-------------------------+
```

---

# Data Flow

The complete detection pipeline is:

```text
Attack
  ↓
Network Traffic
  ↓
Suricata
  ↓
Detection Rule Match
  ↓
eve.json
  ↓
Flask Backend
  ↓
REST API
  ↓
Dashboard Polling
  ↓
Alert Display
```

### Step-by-step

1. Kali generates controlled attack traffic.
2. Traffic travels through the isolated Host-Only network.
3. Suricata monitors the traffic on `eth1`.
4. Active Suricata rules evaluate matching packets.
5. Triggered alerts are written to `eve.json`.
6. Flask reads and parses the alert data.
7. Flask exposes the information through REST APIs.
8. The frontend periodically polls the APIs.
9. The dashboard updates when new alert data becomes available.

---

# Component Roles

| Component                    | Role                                             |
| ---------------------------- | ------------------------------------------------ |
| Kali Linux                   | Simulated attacker, Suricata host, Flask host    |
| Metasploitable2              | Intentionally vulnerable victim machine          |
| VirtualBox Host-Only Network | Isolated laboratory network                      |
| Suricata                     | Passive NIDS sensor                              |
| `eve.json`                   | Structured Suricata event/alert log              |
| Flask                        | Backend API and alert processing                 |
| Dashboard                    | SOC-style monitoring interface                   |
| Nmap                         | Controlled reconnaissance traffic generation     |
| Hydra                        | Controlled SSH brute-force traffic generation    |
| Wireshark                    | Optional packet-level traffic analysis           |
| Git/GitHub                   | Source-code management and project documentation |

---

# Technology Stack

### Operating Systems

* Kali Linux
* Metasploitable2
* Windows host for VirtualBox/browser

### Cybersecurity Tools

* Suricata 8.0.7
* Nmap
* Hydra
* Wireshark

### Development

* Python
* Flask
* HTML
* CSS
* JavaScript
* REST API
* JSON

### Infrastructure

* Oracle VirtualBox
* Host-Only networking
* Git
* GitHub

---

# Lab Network Configuration

The project uses an isolated VirtualBox Host-Only network.

| Parameter              | Value                                |
| ---------------------- | ------------------------------------ |
| Network Type           | VirtualBox Host-Only                 |
| Subnet                 | `192.168.56.0/24`                    |
| Kali Host-Only IP      | `192.168.56.101`                     |
| Kali Capture Interface | `eth1`                               |
| Metasploitable2 IP     | `192.168.56.102`                     |
| Suricata Interface     | `eth1`                               |
| Dashboard              | `http://192.168.56.101:5000`         |
| Suricata Config        | `/etc/suricata/suricata.yaml`        |
| Suricata Rules         | `/etc/suricata/rules/nids-lab.rules` |
| EVE Log                | `/var/log/suricata/eve.json`         |

> **Do not change the Host-Only network configuration during the final demonstration unless there is a specific networking problem.**

---

# Detection Rules

The project currently uses two custom Suricata rules.

## Rule 1 — Nmap Port Scan

```suricata
alert tcp any any -> 192.168.56.102 any (msg:"ET SCAN Possible Nmap Port Scan"; flags:S; flow:stateless; detection_filter:track by_src,count 20,seconds 3; classtype:network-scan; sid:1000001; rev:2;)
```

### Purpose

Detect rapid TCP SYN reconnaissance against the Metasploitable2 victim.

### Important parameters

| Parameter        | Value                             |
| ---------------- | --------------------------------- |
| SID              | `1000001`                         |
| Message          | `ET SCAN Possible Nmap Port Scan` |
| Protocol         | TCP                               |
| Target           | `192.168.56.102`                  |
| Flag             | SYN                               |
| Detection Filter | 20 packets / 3 seconds            |
| Classification   | `network-scan`                    |
| Revision         | `2`                               |

The rule is intentionally scoped to the Metasploitable2 IP to reduce unrelated alert noise.

### Test

```bash
sudo nmap -Pn -sS -p 1-100 192.168.56.102
```

---

## Rule 2 — SSH Brute Force

```suricata
alert tcp any any -> $HOME_NET 22 (msg:"NIDS LAB - SSH Brute Force Activity"; flags:S; flow:stateless; detection_filter:track by_src,count 5,seconds 10; classtype:attempted-admin; sid:1000002; rev:1;)
```

### Purpose

Detect repeated TCP connection attempts toward SSH.

### Important parameters

| Parameter        | Value                                 |
| ---------------- | ------------------------------------- |
| SID              | `1000002`                             |
| Message          | `NIDS LAB - SSH Brute Force Activity` |
| Protocol         | TCP                                   |
| Destination Port | `22`                                  |
| Flag             | SYN                                   |
| Detection Filter | 5 packets / 10 seconds                |
| Classification   | `attempted-admin`                     |
| Revision         | `1`                                   |

### Test

```bash
hydra -l msfadmin -P /usr/share/wordlists/metasploit/unix_passwords.txt -t 6 ssh://192.168.56.102
```

> Use this command only against the intentionally vulnerable Metasploitable2 VM in the isolated laboratory.

---

# Quick Demo Runbook

This is the section to follow during the actual college presentation.

## Demo Requirements

Before starting:

* Kali Linux VM is running.
* Metasploitable2 VM is running.
* Both machines are connected to the same Host-Only network.
* Kali has `192.168.56.101`.
* Metasploitable2 has `192.168.56.102`.
* Suricata is installed.
* The project repository exists at `~/Network-Intrusion-Detection-Lab`.
* Python virtual environment exists.
* Dashboard dependencies are installed.

---

## Step 1 — Verify Kali Interface

### Run in Kali Terminal 1

```bash
ip addr show eth1
```

Expected:

```text
inet 192.168.56.101/24
```

---

## Step 2 — Verify Metasploitable2

### Run in Kali Terminal 1

```bash
ping -c 2 192.168.56.102
```

Expected:

```text
2 packets transmitted, 2 received, 0% packet loss
```

If this fails, **do not start the attack demonstration**. Fix the Host-Only network first.

---

## Step 3 — Start Suricata

### Run in Kali Terminal 1

```bash
sudo suricata -c /etc/suricata/suricata.yaml -i eth1 -l /var/log/suricata -D
```

Verify:

```bash
ps aux | grep '[s]uricata'
```

A Suricata process should be displayed.

---

## Step 4 — Start Flask Dashboard

### Run in Kali Terminal 2

```bash
cd ~/Network-Intrusion-Detection-Lab
source venv/bin/activate

DATA_MODE=suricata \
SURICATA_EVE_PATH=/var/log/suricata/eve.json \
SURICATA_RULES_PATH=/etc/suricata/rules/nids-lab.rules \
FLASK_HOST=0.0.0.0 \
python3 app.py
```

Keep this terminal running.

The important settings are:

```text
DATA_MODE=suricata
SURICATA_EVE_PATH=/var/log/suricata/eve.json
SURICATA_RULES_PATH=/etc/suricata/rules/nids-lab.rules
FLASK_HOST=0.0.0.0
```

---

## Step 5 — Open Dashboard

Open a browser on the Windows host or Kali:

```text
http://192.168.56.101:5000
```

Confirm that the dashboard loads.

The dashboard should be connected to the Suricata data source.

---

# Step 6 — Demonstrate Nmap Detection

### Run in Kali Terminal 3

```bash
sudo nmap -Pn -sS -p 1-100 192.168.56.102
```

This generates rapid TCP SYN traffic toward the Metasploitable2 VM.

The current rule uses:

```text
20 matching SYN packets within 3 seconds
```

A 100-port scan provides enough traffic to exercise the detection threshold much more reliably than a very small port scan.

### Expected dashboard alert

Look at the **Recent Alerts** section.

Expected signature:

```text
ET SCAN Possible Nmap Port Scan
```

Expected SID:

```text
1000001
```

Expected source:

```text
192.168.56.101
```

Expected destination:

```text
192.168.56.102
```

---

# Step 7 — Demonstrate SSH Brute-Force Detection

### Run in Kali Terminal 3

```bash
hydra -l msfadmin -P /usr/share/wordlists/metasploit/unix_passwords.txt -t 6 ssh://192.168.56.102
```

This is a controlled brute-force simulation against the intentionally vulnerable Metasploitable2 VM.

Once sufficient traffic has been generated, stop Hydra with:

```text
Ctrl+C
```

### Expected dashboard alert

Expected signature:

```text
NIDS LAB - SSH Brute Force Activity
```

Expected SID:

```text
1000002
```

Expected source:

```text
192.168.56.101
```

Expected destination:

```text
192.168.56.102
```

Expected destination port:

```text
22
```

---

# Step 8 — Show Raw Suricata Evidence

### Run in Kali Terminal 3

```bash
sudo tail -n 5 /var/log/suricata/fast.log
```

This displays human-readable Suricata alerts.

Then:

```bash
sudo tail -n 5 /var/log/suricata/eve.json
```

This displays structured JSON events.

Look for:

```text
"event_type":"alert"
```

and the corresponding signatures/SIDs.

This is useful during the presentation because it proves that the dashboard is ultimately backed by Suricata-generated event data.

---

# Step 9 — Verify the Backend API

### Check statistics

```bash
curl -s "http://127.0.0.1:5000/api/stats" | python3 -m json.tool
```

### Check latest alerts

```bash
curl -s "http://127.0.0.1:5000/api/alerts?per_page=5&sort_by=timestamp&sort_order=desc" | python3 -m json.tool
```

The latest alerts should correspond to the traffic generated during the demonstration.

---

# Step 10 — Demonstrate Dashboard Investigation

Use the browser to demonstrate the available dashboard views.

Depending on the current UI:

### Alerts

Show:

* Recent alerts
* Severity
* Protocol
* Source IP
* Destination IP
* Alert details
* Raw JSON where available

### Traffic

Show:

* Source IP information
* Destination information
* Protocol information
* Flow information

### Rules

Show the detection rules currently loaded by the application.

### System Status

Show the status of:

* Flask backend
* Suricata data source
* EVE log feed

---

# Live Dashboard Behavior

The dashboard does not require a manual browser refresh for every alert.

The frontend periodically polls the backend API.

The current implementation uses approximately **3-second polling**.

The workflow is:

```text
Suricata writes new alert
        ↓
eve.json changes
        ↓
Flask detects updated file
        ↓
New alert is parsed
        ↓
Frontend polling request
        ↓
Dashboard updates
```

This should be described as:

> **Near-real-time polling/live dashboard updates**

It should not be described as an absolute real-time streaming system.

The project does not use WebSockets or Server-Sent Events for this functionality.

---

# Complete Setup

This section is for rebuilding the environment, not for the final presentation if the environment is already working.

---

## 1. Prerequisites

Required:

* VirtualBox
* Kali Linux
* Metasploitable2
* Python 3
* Git
* Suricata
* Nmap
* Hydra

The host machine must support hardware virtualization.

---

# 2. VirtualBox Network

Use a **Host-Only** network.

The intended topology is:

```text
Windows Host
     |
VirtualBox
     |
     +----------------------------+
     | Host-Only Network           |
     | 192.168.56.0/24             |
     +--------------+-------------+
                    |
            +-------+-------+
            |               |
            v               v
          Kali       Metasploitable2
      192.168.56.101   192.168.56.102
```

Do not expose the vulnerable Metasploitable2 VM directly to the public Internet.

---

# 3. Verify Kali Network

```bash
ip addr
```

Identify the Host-Only interface.

For this project it is:

```text
eth1
```

Verify:

```bash
ip addr show eth1
```

Expected:

```text
192.168.56.101/24
```

If the interface exists but has no address:

```bash
sudo ip addr add 192.168.56.101/24 dev eth1
sudo ip link set eth1 up
```

Then verify:

```bash
ip addr show eth1
```

---

# 4. Verify Metasploitable2

```bash
ping -c 2 192.168.56.102
```

If the target is unreachable, check:

* Both VMs are powered on.
* Both are connected to the same Host-Only network.
* Kali uses `eth1`.
* The target IP is correct.

---

# 5. Install Suricata

If Suricata is not already installed:

```bash
sudo apt update
sudo apt install -y suricata
```

Verify:

```bash
suricata -V
```

The project was tested with:

```text
Suricata 8.0.7
```

---

# 6. Repository Setup

Clone the project:

```bash
cd ~
git clone https://github.com/DEVANSH-140206/Network-Intrusion-Detection-Lab.git
cd Network-Intrusion-Detection-Lab
```

---

# 7. Python Virtual Environment

Create the environment:

```bash
python3 -m venv venv
```

Activate it:

```bash
source venv/bin/activate
```

Install dependencies:

```bash
pip install -r requirements.txt
```

---

# 8. Environment Configuration

Copy the example environment file:

```bash
cp .env.example .env
```

The live Suricata demonstration explicitly uses:

```text
DATA_MODE=suricata
SURICATA_EVE_PATH=/var/log/suricata/eve.json
SURICATA_RULES_PATH=/etc/suricata/rules/nids-lab.rules
FLASK_HOST=0.0.0.0
```

For the final demo, the environment variables are passed directly when starting Flask:

```bash
DATA_MODE=suricata \
SURICATA_EVE_PATH=/var/log/suricata/eve.json \
SURICATA_RULES_PATH=/etc/suricata/rules/nids-lab.rules \
FLASK_HOST=0.0.0.0 \
python3 app.py
```

This is the preferred final demonstration command.

---

# Suricata Configuration

The active configuration is located at:

```text
/etc/suricata/suricata.yaml
```

The project uses:

```text
eth1
```

as the Suricata capture interface.

The custom rules file is:

```text
/etc/suricata/rules/nids-lab.rules
```

The alert output is:

```text
/var/log/suricata/eve.json
```

Before running Suricata, configuration can be validated with:

```bash
sudo suricata -T -c /etc/suricata/suricata.yaml
```

A successful configuration test should indicate that the configuration loaded successfully.

---

# Running Suricata

The current project demonstration command is:

```bash
sudo suricata -c /etc/suricata/suricata.yaml -i eth1 -l /var/log/suricata -D
```

Verify:

```bash
ps aux | grep '[s]uricata'
```

Check the EVE file:

```bash
sudo ls -lh /var/log/suricata/eve.json
```

---

# Running the Dashboard

From the project directory:

```bash
cd ~/Network-Intrusion-Detection-Lab
```

Activate the virtual environment:

```bash
source venv/bin/activate
```

Start Flask:

```bash
DATA_MODE=suricata \
SURICATA_EVE_PATH=/var/log/suricata/eve.json \
SURICATA_RULES_PATH=/etc/suricata/rules/nids-lab.rules \
FLASK_HOST=0.0.0.0 \
python3 app.py
```

Open:

```text
http://192.168.56.101:5000
```

Keep the Flask terminal running while using the dashboard.

---

# Attack and Detection Testing

All attack commands in this documentation are intended only for the isolated laboratory.

The project currently demonstrates two traffic patterns:

1. TCP SYN reconnaissance using Nmap.
2. Repeated SSH connection attempts using Hydra.

---

# Nmap Test

Run:

```bash
sudo nmap -Pn -sS -p 1-100 192.168.56.102
```

This should generate a sufficiently large burst of TCP SYN packets to exercise SID `1000001`.

Expected signature:

```text
ET SCAN Possible Nmap Port Scan
```

Expected SID:

```text
1000001
```

---

# Hydra SSH Test

Run:

```bash
hydra -l msfadmin -P /usr/share/wordlists/metasploit/unix_passwords.txt -t 6 ssh://192.168.56.102
```

This generates repeated SSH connection attempts against the intentionally vulnerable Metasploitable2 machine.

Expected signature:

```text
NIDS LAB - SSH Brute Force Activity
```

Expected SID:

```text
1000002
```

Stop Hydra when the required demonstration traffic has been generated:

```text
Ctrl+C
```

---

# API Reference

The Flask backend provides REST API endpoints for the dashboard.

The exact available routes are implemented in:

```text
backend/routes.py
```

Common endpoints include:

| Endpoint                | Method | Purpose                       |
| ----------------------- | ------ | ----------------------------- |
| `/api/health`           | GET    | Backend health                |
| `/api/stats`            | GET    | Alert statistics              |
| `/api/alerts`           | GET    | Alert listing                 |
| `/api/alerts/<id>`      | GET    | Individual alert              |
| `/api/timeline`         | GET    | Alert timeline                |
| `/api/top-sources`      | GET    | Top source IPs                |
| `/api/top-destinations` | GET    | Top destination IPs           |
| `/api/protocols`        | GET    | Protocol statistics           |
| `/api/categories`       | GET    | Alert category statistics     |
| `/api/top-dest-ports`   | GET    | Targeted destination ports    |
| `/api/flow-pairs`       | GET    | Source/destination flow pairs |
| `/api/filter-options`   | GET    | Dashboard filter data         |
| `/api/rules`            | GET    | Loaded detection rules        |
| `/api/system-status`    | GET    | System component status       |
| `/api/pcap/list`        | GET    | Available PCAP files          |
| `/api/pcap/upload`      | POST   | PCAP upload                   |

---

## API Examples

### Health

```bash
curl -s "http://127.0.0.1:5000/api/health" | python3 -m json.tool
```

### Statistics

```bash
curl -s "http://127.0.0.1:5000/api/stats" | python3 -m json.tool
```

### Latest alerts

```bash
curl -s "http://127.0.0.1:5000/api/alerts?per_page=5&sort_by=timestamp&sort_order=desc" | python3 -m json.tool
```

### Rules

```bash
curl -s "http://127.0.0.1:5000/api/rules" | python3 -m json.tool
```

### System status

```bash
curl -s "http://127.0.0.1:5000/api/system-status" | python3 -m json.tool
```

---

# Validation and Testing

The repository contains automated tests.

Run:

```bash
cd ~/Network-Intrusion-Detection-Lab
source venv/bin/activate
pytest tests/test_app.py -v
```

The test suite covers areas including:

* Alert parsing
* Severity handling
* Statistics
* Filtering
* Pagination
* Timeline processing
* Live file refresh
* API routes
* PCAP handling
* Detection-rule parsing

---

# API Verification Script

With Flask running:

```bash
python tests/verify_api.py
```

This provides an additional check that the live backend endpoints are responding correctly.

---

# Live Refresh Implementation

The live-refresh functionality is implemented across the application.

Important files include:

```text
backend/store.py
backend/routes.py
app.py
frontend/static/js/app.js
```

The backend checks whether the Suricata EVE file has changed.

When new alert records are appended:

```text
eve.json modified
      ↓
backend detects modification
      ↓
new records parsed
      ↓
store updated
      ↓
frontend polling request
      ↓
dashboard updated
```

This allows the dashboard to show new alerts without requiring a manual browser refresh.

---

# Repository Structure

```text
Network-Intrusion-Detection-Lab/
│
├── app.py
├── config.py
├── requirements.txt
├── generate_demo_data.py
├── .env.example
├── .gitignore
├── README.md
│
├── backend/
│   ├── __init__.py
│   ├── parser.py
│   ├── pcap_handler.py
│   ├── routes.py
│   ├── rules.py
│   └── store.py
│
├── frontend/
│   ├── templates/
│   │   └── index.html
│   └── static/
│       ├── css/
│       │   └── style.css
│       └── js/
│           └── app.js
│
├── data/
│   ├── demo/
│   └── uploads/
│
├── tests/
│   ├── __init__.py
│   ├── test_app.py
│   └── verify_api.py
│
├── attack/
│   ├── README.MD
│   └── commands.md
│
├── detection/
│   ├── README.md
│   └── notes.md
│
├── analysis/
│   ├── README.md
│   └── wireshark-notes.md
│
├── dashboard/
│   ├── README.md
│   └── design.md
│
└── docs/
    ├── architecture.md
    ├── methodology.md
    ├── setup.md
    ├── testing.md
    └── week1-progress.md
```

---

# Troubleshooting

## Suricata is not running

Check:

```bash
ps aux | grep '[s]uricata'
```

If it is not running:

```bash
sudo suricata -c /etc/suricata/suricata.yaml -i eth1 -l /var/log/suricata -D
```

---

## Check Suricata configuration

```bash
sudo suricata -T -c /etc/suricata/suricata.yaml
```

---

## Metasploitable2 is unreachable

Check:

```bash
ping -c 2 192.168.56.102
```

Then check:

```bash
ip addr show eth1
```

Make sure Kali is using:

```text
192.168.56.101
```

and the two VMs are connected to the same Host-Only network.

---

## `eve.json` is not updating

Check:

```bash
sudo ls -lh /var/log/suricata/eve.json
```

Then:

```bash
ps aux | grep '[s]uricata'
```

Confirm that Suricata is running on:

```text
eth1
```

You can also inspect:

```bash
sudo tail -n 10 /var/log/suricata/eve.json
```

---

## Nmap does not trigger SID 1000001

The current rule requires:

```text
20 matching SYN packets within 3 seconds
```

Use:

```bash
sudo nmap -Pn -sS -p 1-100 192.168.56.102
```

Do not rely on a very small port scan.

---

## Hydra does not trigger SID 1000002

The current rule requires:

```text
5 matching SSH SYN attempts within 10 seconds
```

Use:

```bash
hydra -l msfadmin -P /usr/share/wordlists/metasploit/unix_passwords.txt -t 6 ssh://192.168.56.102
```

Make sure the Metasploitable2 SSH service is reachable.

---

## Dashboard cannot be opened

Check Flask:

```bash
curl -s "http://127.0.0.1:5000/api/health"
```

Check that Flask was started using:

```text
FLASK_HOST=0.0.0.0
```

Then open:

```text
http://192.168.56.101:5000
```

---

## Port 5000 is already in use

Check:

```bash
sudo lsof -i :5000
```

or:

```bash
ss -tulpn | grep 5000
```

Stop the previous Flask process if necessary.

---

# Final Presentation Checklist

Before the presentation:

* [ ] Kali VM is running.
* [ ] Metasploitable2 VM is running.
* [ ] Host-Only network is working.
* [ ] Kali IP is `192.168.56.101`.
* [ ] Metasploitable2 IP is `192.168.56.102`.
* [ ] Kali capture interface is `eth1`.
* [ ] Suricata is installed.
* [ ] Suricata configuration has been validated.
* [ ] Custom rules exist.
* [ ] Python virtual environment exists.
* [ ] Python dependencies are installed.
* [ ] Dashboard starts successfully.
* [ ] Browser can open `http://192.168.56.101:5000`.
* [ ] Nmap test works.
* [ ] Hydra test works.
* [ ] Dashboard updates without manual refresh.
* [ ] API responds.
* [ ] `eve.json` receives alerts.
* [ ] `fast.log` receives alerts.

---

# Recommended Live Presentation Sequence

For the actual evaluation, use this order:

```text
1. Start VMs
       ↓
2. Verify Kali IP
       ↓
3. Ping Metasploitable2
       ↓
4. Start Suricata
       ↓
5. Start Flask
       ↓
6. Open Dashboard
       ↓
7. Explain architecture
       ↓
8. Run Nmap
       ↓
9. Show Nmap alert appearing
       ↓
10. Run Hydra
       ↓
11. Show SSH alert appearing
       ↓
12. Show eve.json / fast.log
       ↓
13. Show API
       ↓
14. Show dashboard investigation views
       ↓
15. Explain limitations/future work
```

---

# Post-Demo Cleanup

After the presentation, stop the services.

## Stop Suricata

```bash
sudo pkill suricata
```

## Stop Flask

If Flask is running in the foreground:

```text
Ctrl+C
```

Alternatively:

```bash
pkill -f "python.*app.py"
```

Verify:

```bash
ps aux | grep -E 'suricata|python.*app.py' | grep -v grep
```

If a clean future demonstration is required, the generated logs can be cleared:

```bash
sudo truncate -s 0 /var/log/suricata/eve.json
sudo truncate -s 0 /var/log/suricata/fast.log
```

> Only clear the logs when you intentionally want a fresh demonstration. Do not clear them before collecting evidence required for evaluation.

---

# Limitations

The current implementation has several intentional limitations.

### 1. Passive IDS

Suricata is used as a passive NIDS sensor.

The project does not:

* Block traffic
* Drop packets
* Automatically ban IP addresses
* Operate as an IPS

---

### 2. Limited Detection Rules

The project currently focuses on two controlled traffic patterns:

* Nmap-style TCP SYN reconnaissance
* SSH brute-force activity

It is not intended to detect every possible attack.

---

### 3. Controlled Virtual Environment

The system operates inside an isolated VirtualBox laboratory.

It does not reproduce:

* Large enterprise networks
* Multiple production subnets
* Distributed sensors
* Enterprise SIEM infrastructure
* Production-scale traffic volumes

---

### 4. Signature-Based Detection

The current detection approach uses deterministic Suricata signatures and detection filters.

The project does not currently implement:

* Machine learning
* AI-based detection
* Behavioral anomaly detection
* Automated threat intelligence correlation

---

### 5. Near-Real-Time Polling

The dashboard uses periodic HTTP polling to retrieve updated data.

It is therefore better described as:

> **Near-real-time dashboard monitoring**

rather than absolute real-time streaming.

---

### 6. Educational Project

The system is intended for:

* Academic demonstration
* Cybersecurity learning
* Controlled testing
* Project evaluation

It should not be treated as a production security platform.

---

# Future Improvements

Possible future extensions include:

* More Suricata detection signatures
* Additional attack simulations
* Improved alert correlation
* Authentication and role-based dashboard access
* Persistent database storage
* PCAP-to-alert investigation workflows
* Email or notification integration
* Threat-intelligence enrichment
* Centralized logging
* Multi-sensor support
* Enterprise-style SIEM integration
* Automated incident-response workflows
* Advanced anomaly detection

These are future possibilities and are not claimed as currently implemented functionality.

---

# Learning Outcomes

Through this project, the team gains practical exposure to:

* Network security monitoring
* NIDS architecture
* Suricata configuration
* Signature-based intrusion detection
* TCP SYN reconnaissance
* SSH brute-force traffic
* Network traffic analysis
* Wireshark
* Linux administration
* Python
* Flask REST APIs
* JSON event processing
* Frontend dashboard development
* VirtualBox networking
* Git/GitHub
* Cybersecurity testing methodology
* SOC monitoring concepts

---

# Team Responsibilities

The project team responsibilities are organized around the technical components of the system.

| Member             | Project Focus                      | Responsibilities                                                      |
| ------------------ | ---------------------------------- | --------------------------------------------------------------------- |
| Devansh Chaubey    | Attack Simulation & Reconnaissance | Nmap reconnaissance, Hydra traffic generation, attack-side testing    |
| Divija Srivastava  | Suricata NIDS & Detection          | Suricata configuration, detection rules, sensor configuration         |
| Manya              | Victim Environment & Analysis      | Metasploitable2 environment, victim-side services, Wireshark analysis |
| Anshika Srivastava | Dashboard & Backend                | Flask backend, alert processing, dashboard implementation             |
| Sharat Chodhary    | Integration & Testing              | End-to-end testing, validation, integration, demonstration support    |

---

# Security and Ethical Use

This project contains demonstrations of network reconnaissance and credential brute-force techniques.

All such activities must be performed only:

* On systems you own or are explicitly authorized to test.
* Inside the isolated project laboratory.
* Against the intentionally vulnerable Metasploitable2 target.

The documented Nmap and Hydra commands are intended for the controlled VirtualBox laboratory only.

Do **not** use these commands against:

* Public websites
* College infrastructure
* Company systems
* Other people's computers
* Public IP addresses
* Networks without explicit authorization

Metasploitable2 is intentionally vulnerable and exists specifically for controlled security training.

---

# GitHub Usage

The project source code and documentation are maintained in Git.

Remote repository:

```text
https://github.com/DEVANSH-140206/Network-Intrusion-Detection-Lab
```

After making documentation or code changes:

```bash
git status
```

Review the changes:

```bash
git diff
```

Stage the changes:

```bash
git add .
```

Commit:

```bash
git commit -m "Update project documentation"
```

Push:

```bash
git push origin main
```

For future updates, always verify the working tree before committing:

```bash
git status
```

---

# Final Project Statement

The Network Intrusion Detection Lab demonstrates a complete, controlled cybersecurity monitoring workflow:

```text
                CONTROLLED ATTACK
                       |
                       v
              NETWORK TRAFFIC
                       |
                       v
              +----------------+
              |    SURICATA    |
              |   PASSIVE NIDS |
              +-------+--------+
                      |
                      v
                  eve.json
                      |
                      v
              +---------------+
              | FLASK BACKEND |
              +-------+-------+
                      |
                      v
              +---------------+
              | SOC DASHBOARD |
              +---------------+
                      |
                      v
              SECURITY ANALYSIS
```

The project demonstrates how network traffic can be generated in a controlled environment, detected using a passive NIDS, converted into structured security events, processed by a backend service, and presented through a SOC-style monitoring dashboard.

It provides a practical small-scale representation of the fundamental workflow used in network security monitoring environments.

---
