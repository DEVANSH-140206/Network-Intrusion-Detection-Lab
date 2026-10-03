# NIDS Lab — Final Demo Runbook

## Network Intrusion Detection Lab

A small-scale simulation of a passive **Enterprise Network Intrusion Detection System (NIDS)** operating as part of a **Security Operations Center (SOC)**.

---

## 1. LAB ARCHITECTURE

```
Windows Host
    ↓
Browser  (http://192.168.56.101:5000)
    ↓
Flask Dashboard
    ↓
Kali Linux  (192.168.56.101)
    ├── Suricata  (IDS — listens on eth1)
    ├── Nmap      (TCP SYN reconnaissance)
    ├── Hydra     (SSH brute-force simulation)
    └── Flask     (SOC dashboard web server)
    ↓
Host-Only Network  (192.168.56.0/24)
    ↓
Metasploitable2  (<METASPLOITABLE-IP>)
```

### Component Roles

| Component | Role |
|---|---|
| **Kali Linux** | Attacker/IDS machine — runs Suricata and the Flask dashboard |
| **Metasploitable2** | Intentionally vulnerable victim — generates real target traffic |
| **Suricata** | Passive NIDS — inspects eth1, writes structured events to eve.json |
| **Nmap** | Generates controlled TCP SYN reconnaissance traffic |
| **Hydra** | Simulates SSH brute-force login attempts |
| **Flask** | SOC-style web dashboard that reads and visualizes eve.json |
| **eve.json** | Suricata’s structured JSON alert log — the live data feed for the dashboard |
| **Wireshark** | Optional packet-level evidence — captures raw traffic on eth1 |
| **VirtualBox Host-Only Network** | Isolated lab network — keeps all traffic inside the lab environment |

---

## 2. IMPORTANT IP ADDRESSES

| Machine | IP Address |
|---|---|
| Kali Linux (attacker + dashboard host) | `192.168.56.101` |
| Kali capture interface | `eth1` |
| Metasploitable2 (victim) | **Must be discovered before the demo — see Step 4** |
| SOC Dashboard URL | `http://192.168.56.101:5000` |

> **IMPORTANT:** Do NOT assume the Metasploitable2 IP is any fixed value.
> It must be discovered with `nmap -sn 192.168.56.0/24` before every demo.
> Wherever you see `<METASPLOITABLE-IP>` in this runbook, substitute the actual IP you find.

---

## 3. BEFORE STARTING THE DEMO

1. Start **Kali Linux** in VirtualBox.
2. Start **Metasploitable2** in VirtualBox.
3. Confirm both VMs are connected to the same **Host-Only** network (`192.168.56.0/24`).
4. Do **not** change the network adapter settings during the demo.
5. Open a browser on the **Windows host** — it will be used for the dashboard.

---

## 4. TERMINAL 1 — DISCOVER METASPLOITABLE2

Open a terminal on Kali and run:

```bash
nmap -sn 192.168.56.0/24
```

**What to look for:**
- `192.168.56.101` is Kali itself — skip it.
- The second live host (typically showing many open ports or "Metasploitable" in its hostname) is the victim.
- Note that IP — it is your `<METASPLOITABLE-IP>` for the rest of the demo.

---

## 5. VERIFY KALI IDS INTERFACE

```bash
ip addr show eth1
```

**Expected output (excerpt):**
```
inet 192.168.56.101/24
```

`eth1` is the Host-Only laboratory interface that Suricata uses to capture traffic.
If you do not see `192.168.56.101` on `eth1`, stop and fix the VirtualBox network configuration before continuing.

---

## 6. OPTIONAL CLEAN START

If Suricata or Flask from a previous session are still running, stop them first:

```bash
sudo pkill suricata
```

```bash
pkill -f "python.*app.py"
```

Verify both are stopped (no output = clean):

```bash
ps aux | grep -E 'suricata|python.*app.py' | grep -v grep
```

---

## 7. TERMINAL 1 — START SURICATA

```bash
sudo suricata -c /etc/suricata/suricata.yaml -i eth1 -l /var/log/suricata -D
```

**Verify Suricata is running:**

```bash
ps aux | grep suricata | grep -v grep
```

**Expected:** A line containing `suricata` is visible.

**What Suricata does:**
- Reads network traffic from `eth1` in passive (IDS) mode.
- Writes structured alert events to `/var/log/suricata/eve.json`.
- Writes a fast human-readable log to `/var/log/suricata/fast.log`.

---

## 8. TERMINAL 2 — START FLASK DASHBOARD

Open a **second terminal** on Kali:

```bash
cd ~/Network-Intrusion-Detection-Lab
```

```bash
source venv/bin/activate
```

```bash
DATA_MODE=suricata SURICATA_EVE_PATH=/var/log/suricata/eve.json FLASK_HOST=0.0.0.0 python3 app.py
```

**What to expect:**
```
Starting NIDS Dashboard on http://0.0.0.0:5000
```

Flask is now serving the SOC dashboard on port 5000, accessible from the Windows host browser.

---

## 9. WINDOWS — OPEN SOC DASHBOARD

On the Windows host browser, navigate to:

```
http://192.168.56.101:5000
```

Navigate to: **Dashboard → Recent Alerts**

This is the primary live-detection view for the demo.

> **IMPORTANT:** The dashboard polls for new Suricata alerts every **3 seconds** automatically.
> You do **NOT** need to refresh the browser manually — new alerts appear on their own.

---

## 10. WHAT TO SAY BEFORE THE ATTACK

> *"The dashboard is currently monitoring the Suricata event stream. I will now generate controlled network traffic from the Kali attacker against the isolated Metasploitable2 victim and demonstrate real-time detection and visualization."*

---

## 11. TERMINAL 3 — NMAP RECONNAISSANCE

Open a **third terminal** on Kali and run:

```bash
sudo nmap -Pn -sS -p 21,25,80,443,3306 <METASPLOITABLE-IP>
```

**What this does:**
Generates controlled TCP SYN reconnaissance traffic against the victim.

**Expected Suricata detection:**

| Field | Value |
|---|---|
| Signature | `NIDS LAB - TCP SYN Reconnaissance Detected` |
| SID | `1000001` |

**Where to look:**

```
Windows Browser → Dashboard → Recent Alerts
```

The new alert should appear **automatically within approximately 3 seconds**.
No manual browser refresh is needed.

---

## 12. SECOND NMAP DEMONSTRATION

```bash
sudo nmap -Pn -sS -p- <METASPLOITABLE-IP>
```

This demonstrates broader TCP SYN port scanning across all 65535 ports, producing additional reconnaissance alerts in the dashboard.

---

## 13. OPTIONAL NMAP SERVICE ENUMERATION

```bash
sudo nmap -Pn -sS -sV -p 1-1000 <METASPLOITABLE-IP>
```

This demonstrates combined reconnaissance and service version identification.
Keep this step optional — run it only if time permits, as it takes longer.

---

## 14. TERMINAL 3 — HYDRA SSH BRUTE-FORCE DEMONSTRATION

```bash
hydra -l msfadmin -P /usr/share/wordlists/metasploit/unix_passwords.txt -t 6 ssh://<METASPLOITABLE-IP>
```

**Expected Suricata detection:**

| Field | Value |
|---|---|
| Signature | `NIDS LAB - SSH Brute Force Activity` |
| SID | `1000002` |

**Where to look:**

```
Windows Browser → Dashboard → Recent Alerts
```

The new alert should appear **automatically within approximately 3 seconds**.
No manual browser refresh is needed.

---

## 15. ALERTS PAGE

After the attacks, navigate to the detailed investigation view:

```
Windows Browser → Dashboard → Alerts
```

This page shows full alert records with the following columns:

| Column | Description |
|---|---|
| Timestamp | Date and time the event was recorded |
| Signature | Suricata rule name that fired |
| Severity | Critical / High / Medium / Low |
| Category | Suricata alert category |
| Source | Attacker source IP address |
| Destination | Victim destination IP address |
| Protocol | Network protocol (e.g., TCP) |
| SID | Suricata rule signature ID |
| Flow ID | Suricata internal flow identifier |

You can filter by Severity, Category, Protocol, Source IP, and Destination IP.

---

## 16. TERMINAL 4 — RAW SURICATA EVIDENCE

Show the raw evidence behind the dashboard to the evaluator.

**Fast log (human-readable):**

```bash
sudo tail -n 10 /var/log/suricata/fast.log
```

**Structured JSON event log:**

```bash
sudo tail -n 10 /var/log/suricata/eve.json
```

This demonstrates that the dashboard data comes directly from Suricata’s live output — no manual injection, no fake data.

---

## 17. COMPLETE DATA FLOW

```
Nmap / Hydra
    ↓
Kali Attacker  (192.168.56.101)
    ↓
Host-Only Network  (192.168.56.0/24)
    ↓
Metasploitable2  (<METASPLOITABLE-IP>)
    ↓
Suricata on eth1
    ↓
Custom Detection Rules
    ↓
/var/log/suricata/eve.json
    ↓
Flask Backend  (store.refresh_if_modified)
    ↓
Dashboard API  (/api/alerts, /api/stats)
    ↓
Live polling (every 3 seconds)
    ↓
Recent Alerts table updated
    ↓
SOC Dashboard  (http://192.168.56.101:5000)
```

**Active custom detection rules:**

```
SID 1000001 — TCP SYN Reconnaissance Detected
SID 1000002 — SSH Brute Force Activity
```

---

## 18. DETECTION RULES

### Rule SID 1000001 — TCP SYN Reconnaissance Detected

Detects repeated TCP SYN traffic patterns that are characteristic of network reconnaissance and port scanning activity.

**What it detects:** Bursts of TCP SYN packets from a single source toward multiple ports — consistent with scanning tools like Nmap.

> **Note:** The rule detects the *traffic pattern*. It does not claim to prove the source tool was Nmap.

---

### Rule SID 1000002 — SSH Brute Force Activity

Detects repeated TCP SYN connection attempts directed at port 22 (SSH) from a single source.

**What it detects:** High-frequency connection attempts to the SSH service — consistent with automated credential-stuffing or brute-force tools.

> **Note:** The rule detects connection attempt patterns. It does not confirm whether any authentication succeeded.

---

## 19. OPTIONAL — WIRESHARK PACKET EVIDENCE

For additional packet-level evidence during the demo:

1. Open **Wireshark** on Kali.
2. Select capture interface: `eth1`.
3. Start capture.

**Useful display filters:**

| Purpose | Filter |
|---|---|
| All TCP traffic | `tcp` |
| Only SYN packets (reconnaissance) | `tcp.flags.syn == 1` |
| SSH connection attempts | `tcp.dstport == 22` |

Wireshark is **optional** — it is not required for the core demonstration.
Use it only if the evaluator asks for packet-level evidence.

---

## 20. EXACT FINAL DEMO ORDER — CHECKLIST

```
[ ] STEP 1   Start Metasploitable2 in VirtualBox.

[ ] STEP 2   Discover victim IP:
             nmap -sn 192.168.56.0/24
             Note the Metasploitable2 IP as <METASPLOITABLE-IP>.

[ ] STEP 3   Verify Kali interface:
             ip addr show eth1
             Confirm: inet 192.168.56.101/24

[ ] STEP 4   Start Suricata:
             sudo suricata -c /etc/suricata/suricata.yaml -i eth1 -l /var/log/suricata -D
             Verify: ps aux | grep suricata | grep -v grep

[ ] STEP 5   Start Flask:
             cd ~/Network-Intrusion-Detection-Lab
             source venv/bin/activate
             DATA_MODE=suricata SURICATA_EVE_PATH=/var/log/suricata/eve.json FLASK_HOST=0.0.0.0 python3 app.py

[ ] STEP 6   Open Windows browser:
             http://192.168.56.101:5000

[ ] STEP 7   Stay on:
             Dashboard → Recent Alerts

[ ] STEP 8   Run Nmap reconnaissance:
             sudo nmap -Pn -sS -p 21,25,80,443,3306 <METASPLOITABLE-IP>

[ ] STEP 9   Show on dashboard:
             NIDS LAB - TCP SYN Reconnaissance Detected  (SID 1000001)

[ ] STEP 10  Run Hydra SSH brute-force:
             hydra -l msfadmin -P /usr/share/wordlists/metasploit/unix_passwords.txt -t 6 ssh://<METASPLOITABLE-IP>

[ ] STEP 11  Show on dashboard:
             NIDS LAB - SSH Brute Force Activity  (SID 1000002)

[ ] STEP 12  Open Alerts page for detailed view:
             Dashboard → Alerts

[ ] STEP 13  Show fast.log evidence:
             sudo tail -n 10 /var/log/suricata/fast.log

[ ] STEP 14  Show eve.json evidence:
             sudo tail -n 10 /var/log/suricata/eve.json
```

---

## 21. FINAL EXPLANATION TO EVALUATOR

> *"Our project is a small-scale simulation of a passive Enterprise Network Intrusion Detection System operating as part of a Security Operations Center. Kali generates controlled attack traffic against an intentionally vulnerable Metasploitable2 server. Suricata monitors the laboratory interface, detects suspicious traffic using custom rules, and writes structured events to eve.json. Our Flask dashboard consumes this live event stream and visualizes the detections in a SOC-style interface."*

---

## 22. TEAM MEMBER RESPONSIBILITIES

| Member | Responsibility |
|---|---|
| **Devansh Chaubey** | Attack & Reconnaissance — Nmap scanning, Hydra brute-force simulation, controlled attack traffic generation |
| **Divija Srivastava** | Suricata IDS — Suricata configuration, eth1 packet capture, custom detection rules, eve.json output |
| **Manya** | Metasploitable2 & Traffic Analysis — victim environment setup, victim-side traffic, Wireshark captures |
| **Anshika Srivastava** | Flask Dashboard — Flask web app, REST API, eve.json parsing, live polling, SOC dashboard visualization |
| **Sharat Chodhary** | Integration & Testing — end-to-end pipeline testing, Nmap/Hydra integration testing, live dashboard validation |

---

## 23. TROUBLESHOOTING

### Dashboard does not open in browser

Check Flask is running:
```bash
ps aux | grep "python.*app.py" | grep -v grep
```

Check Kali IP is correct:
```bash
ip addr show eth1
```

### Suricata not running

```bash
ps aux | grep suricata | grep -v grep
```

If no output, restart Suricata:
```bash
sudo suricata -c /etc/suricata/suricata.yaml -i eth1 -l /var/log/suricata -D
```

### No alerts appearing on dashboard

Verify victim IP is reachable:
```bash
nmap -sn 192.168.56.0/24
```

Check Suricata is writing to eve.json:
```bash
sudo tail -n 10 /var/log/suricata/eve.json
```

If eve.json is empty or not being written, Suricata may not be capturing on `eth1`.

### Old alerts visible, no new alerts showing

- Stay on **Dashboard → Recent Alerts** (not the Alerts investigation page).
- Run a fresh Nmap command.
- Wait approximately 3 seconds — the dashboard polls automatically.
- Do **not** manually edit eve.json.
- Do not restart Flask or Suricata mid-demo unless there is a real failure.

---

## 24. IMPORTANT DEMO RULES

- Keep Kali and Metasploitable2 on the isolated Host-Only network only.
- Attack only the laboratory Metasploitable2 target.
- Discover the victim IP before the demo starts — never assume it.
- Do not change Suricata configuration during the demo.
- Do not manually edit or truncate eve.json.
- Do not manually add fake alerts to the dashboard.
- Keep Flask running throughout the demonstration.
- Keep Suricata running throughout the demonstration.
- Keep the Windows browser open on the dashboard.
- Use **Recent Alerts** for live detection demonstration.
- Use **Alerts** page for detailed investigation demonstration.
- Use `fast.log` and `eve.json` as raw evidence.
- Wireshark is optional packet-level supplementary evidence.

---

## 25. ONE-MINUTE EMERGENCY DEMO

If time is short or something has failed, run only this minimal sequence:

**Terminal 1 — Suricata:**
```bash
sudo suricata -c /etc/suricata/suricata.yaml -i eth1 -l /var/log/suricata -D
```

**Terminal 2 — Flask:**
```bash
cd ~/Network-Intrusion-Detection-Lab
source venv/bin/activate
DATA_MODE=suricata SURICATA_EVE_PATH=/var/log/suricata/eve.json FLASK_HOST=0.0.0.0 python3 app.py
```

**Windows browser:**
```
http://192.168.56.101:5000
```
Navigate to: **Dashboard → Recent Alerts**

**Terminal 3 — Reconnaissance:**
```bash
sudo nmap -Pn -sS -p 21,25,80,443,3306 <METASPLOITABLE-IP>
```

**Terminal 3 — Brute-force:**
```bash
hydra -l msfadmin -P /usr/share/wordlists/metasploit/unix_passwords.txt -t 6 ssh://<METASPLOITABLE-IP>
```

Show **Alerts** page. Done.

---

## 26. PROJECT SUCCESS CRITERIA

```
ATTACK
  ↓
NETWORK TRAFFIC
  ↓
SURICATA DETECTION
  ↓
EVE.JSON EVENT
  ↓
FLASK BACKEND
  ↓
SOC DASHBOARD
  ↓
LIVE ALERT (automatic, no refresh)
```

**Primary demonstrations:**

```
Nmap  →  TCP SYN Reconnaissance Detected  (SID 1000001)

Hydra  →  SSH Brute Force Activity  (SID 1000002)
```

Both alerts appear automatically in the dashboard within approximately 3 seconds of the attack running — **no manual browser refresh required**.

---

## Security & Ethical Use

All scanning, traffic generation, reconnaissance, and simulated attack activities in this project are performed exclusively against intentionally vulnerable systems inside the controlled VirtualBox laboratory.
No unauthorized systems or networks are targeted.

---

*Network Intrusion Detection Lab — Controlled Environment · Practical Security · Real-Time Visualization*
