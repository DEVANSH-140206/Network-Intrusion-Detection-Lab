"""
Eve.json demo data generator.
Run this script once to regenerate sample_eve.json with realistic lab data.
"""

import json
import random
from datetime import datetime, timedelta

random.seed(42)

# Lab IP ranges
KALI_IPS = ["192.168.56.101", "192.168.56.102"]
META_IPS = ["192.168.56.110", "192.168.56.111"]
INTERNAL_IPS = ["192.168.56.1", "192.168.56.2", "192.168.56.20", "192.168.56.50"]

SIGNATURES = [
    {"sid": 2010935, "gid": 1, "sig": "ET SCAN Nmap Scripting Engine User-Agent Detected", "cat": "Attempted Information Leak", "severity": 2},
    {"sid": 2000537, "gid": 1, "sig": "ET SCAN Potential SSH Scan", "cat": "Attempted Information Leak", "severity": 2},
    {"sid": 2001219, "gid": 1, "sig": "ET SCAN Potential VNC Scan 5800-5820", "cat": "Attempted Information Leak", "severity": 2},
    {"sid": 2009358, "gid": 1, "sig": "ET SCAN Suspicious inbound to mySQL port 3306", "cat": "Potentially Bad Traffic", "severity": 2},
    {"sid": 2001569, "gid": 1, "sig": "ET SCAN Potential RDP Scan", "cat": "Attempted Information Leak", "severity": 2},
    {"sid": 2010050, "gid": 1, "sig": "ET SCAN Nmap OS Detection Probe", "cat": "Attempted Information Leak", "severity": 2},
    {"sid": 2010936, "gid": 1, "sig": "ET SCAN Nmap SYN Scan Detected", "cat": "Attempted Information Leak", "severity": 2},
    {"sid": 2010937, "gid": 1, "sig": "ET SCAN Nmap Version Scan Detected", "cat": "Attempted Information Leak", "severity": 2},
    {"sid": 2001978, "gid": 1, "sig": "ET SCAN Shellcode Exploit Attempt", "cat": "Attempted User Privilege Gain", "severity": 1},
    {"sid": 2002910, "gid": 1, "sig": "ET EXPLOIT MS08-067 Possible RPC Request with Shell Code", "cat": "Attempted User Privilege Gain", "severity": 1},
    {"sid": 2003068, "gid": 1, "sig": "ET EXPLOIT SAMBA Buffer Overflow Attempt", "cat": "Attempted User Privilege Gain", "severity": 1},
    {"sid": 2019284, "gid": 1, "sig": "ET EXPLOIT MS17-010 EternalBlue SMB Remote Windows Code Execution", "cat": "Attempted User Privilege Gain", "severity": 1},
    {"sid": 2100498, "gid": 1, "sig": "GPL ATTACK_RESPONSE id check returned root", "cat": "Potentially Bad Traffic", "severity": 2},
    {"sid": 2001219, "gid": 1, "sig": "ET SCAN Potential FTP Brute Force", "cat": "Attempted Administrator Privilege Gain", "severity": 1},
    {"sid": 2008446, "gid": 1, "sig": "ET POLICY Telnet Login Incorrect", "cat": "Potentially Bad Traffic", "severity": 3},
    {"sid": 2011716, "gid": 1, "sig": "ET WEB_SERVER ColdFusion administrator access", "cat": "Web Application Attack", "severity": 2},
    {"sid": 2024987, "gid": 1, "sig": "ET MALWARE Meterpreter or Metasploit Framework Stager", "cat": "A Network Trojan was Detected", "severity": 1},
    {"sid": 2001876, "gid": 1, "sig": "ET TROJAN Metasploit Meterpreter reverse shell", "cat": "A Network Trojan was Detected", "severity": 1},
    {"sid": 2012887, "gid": 1, "sig": "ET POLICY ICMP Flood", "cat": "Denial of Service", "severity": 2},
    {"sid": 2009282, "gid": 1, "sig": "ET SCAN XMAS Scan", "cat": "Attempted Information Leak", "severity": 3},
    {"sid": 2009283, "gid": 1, "sig": "ET SCAN NULL Scan", "cat": "Attempted Information Leak", "severity": 3},
    {"sid": 2001628, "gid": 1, "sig": "ET SCAN Nmap -sA (ACK Scan)", "cat": "Attempted Information Leak", "severity": 3},
    {"sid": 2009284, "gid": 1, "sig": "ET SCAN Nmap FIN Scan", "cat": "Attempted Information Leak", "severity": 3},
    {"sid": 2101411, "gid": 1, "sig": "GPL SNMP public access UDP", "cat": "Attempted Information Leak", "severity": 3},
    {"sid": 2002992, "gid": 1, "sig": "ET POLICY GNU/Linux APT-HTTP request", "cat": "Not Suspicious Traffic", "severity": 3},
    {"sid": 2003325, "gid": 1, "sig": "ET SCAN LDAP Null Base and Bind Request", "cat": "Attempted Information Leak", "severity": 3},
    {"sid": 2012999, "gid": 1, "sig": "ET WEB_SPECIFIC_APPS phpMyAdmin Access", "cat": "Web Application Attack", "severity": 2},
    {"sid": 2013504, "gid": 1, "sig": "ET EXPLOIT vsftpd 2.3.4 Backdoor Command Execution", "cat": "Attempted User Privilege Gain", "severity": 1},
    {"sid": 2017394, "gid": 1, "sig": "ET EXPLOIT UnrealIRCd Backdoor Response", "cat": "Attempted User Privilege Gain", "severity": 1},
    {"sid": 2014701, "gid": 1, "sig": "ET DOS Possible Slow HTTP DoS Attack (in progress)", "cat": "Denial of Service", "severity": 2},
]

PROTOS = ["TCP", "UDP", "ICMP"]
HIGH_PORTS = list(range(32000, 65535))
COMMON_DEST_PORTS = [21, 22, 23, 25, 80, 139, 443, 445, 3306, 3389, 4444, 5432, 5900, 8080, 8443]

def random_ts(base: datetime, spread_seconds: int) -> str:
    delta = timedelta(seconds=random.randint(0, spread_seconds))
    t = base + delta
    return t.strftime("%Y-%m-%dT%H:%M:%S.%f")[:-3] + "+0530"

def make_alert(ts: str, sig_info: dict, src_ip: str, dst_ip: str,
               src_port: int, dst_port: int, proto: str, flow_id: int) -> dict:
    return {
        "timestamp": ts,
        "flow_id": flow_id,
        "event_type": "alert",
        "src_ip": src_ip,
        "src_port": src_port,
        "dest_ip": dst_ip,
        "dest_port": dst_port,
        "proto": proto,
        "alert": {
            "action": "allowed",
            "gid": sig_info["gid"],
            "signature_id": sig_info["sid"],
            "rev": random.randint(1, 20),
            "signature": sig_info["sig"],
            "category": sig_info["cat"],
            "severity": sig_info["severity"],
        }
    }

def generate_events():
    events = []
    base = datetime(2026, 9, 29, 6, 0, 0)
    flow_counter = 1000000000

    # Nmap scan burst from Kali
    nmap_sigs = [s for s in SIGNATURES if "Nmap" in s["sig"] or "SCAN" in s["sig"]]
    for _ in range(80):
        sig = random.choice(nmap_sigs)
        src = random.choice(KALI_IPS)
        dst = random.choice(META_IPS)
        proto = "TCP" if sig["severity"] <= 2 else random.choice(["TCP", "UDP"])
        ts = random_ts(base, 3600)
        events.append(make_alert(ts, sig, src, dst,
                                 random.choice(HIGH_PORTS),
                                 random.choice(COMMON_DEST_PORTS),
                                 proto, flow_counter))
        flow_counter += 1

    # Exploitation attempts
    exploit_sigs = [s for s in SIGNATURES if "EXPLOIT" in s["sig"] or "MALWARE" in s["sig"] or "TROJAN" in s["sig"]]
    for _ in range(30):
        sig = random.choice(exploit_sigs)
        src = random.choice(KALI_IPS)
        dst = random.choice(META_IPS)
        ts = random_ts(base + timedelta(hours=1), 3600)
        events.append(make_alert(ts, sig, src, dst,
                                 random.choice(HIGH_PORTS),
                                 random.choice([445, 139, 21, 22, 4444, 6667]),
                                 "TCP", flow_counter))
        flow_counter += 1

    # Mixed internal traffic
    for _ in range(40):
        sig = random.choice(SIGNATURES)
        src = random.choice(KALI_IPS + INTERNAL_IPS)
        dst = random.choice(META_IPS + INTERNAL_IPS)
        if src == dst:
            dst = META_IPS[0]
        proto = random.choice(PROTOS)
        if proto == "ICMP":
            src_port, dst_port = 0, 0
        else:
            src_port = random.choice(HIGH_PORTS)
            dst_port = random.choice(COMMON_DEST_PORTS)
        ts = random_ts(base + timedelta(hours=2), 7200)
        events.append(make_alert(ts, sig, src, dst, src_port, dst_port, proto, flow_counter))
        flow_counter += 1

    # DoS / policy events
    dos_sigs = [s for s in SIGNATURES if "DoS" in s["sig"] or "ICMP" in s["sig"] or "POLICY" in s["sig"]]
    for _ in range(20):
        sig = random.choice(dos_sigs)
        src = random.choice(KALI_IPS)
        dst = random.choice(META_IPS)
        proto = "ICMP" if "ICMP" in sig["sig"] else "TCP"
        src_port = 0 if proto == "ICMP" else random.choice(HIGH_PORTS)
        dst_port = 0 if proto == "ICMP" else random.choice(COMMON_DEST_PORTS)
        ts = random_ts(base + timedelta(hours=4), 3600)
        events.append(make_alert(ts, sig, src, dst, src_port, dst_port, proto, flow_counter))
        flow_counter += 1

    # Some non-alert event types (stats, flow) - parser should skip these
    events.append({"timestamp": random_ts(base, 60), "event_type": "stats", "uptime": 1234})
    events.append({"timestamp": random_ts(base, 60), "event_type": "flow",
                   "src_ip": "192.168.56.101", "dest_ip": "192.168.56.110",
                   "flow": {"pkts_toserver": 10}})
    # Malformed lines will be added as raw strings in the file separately

    # Sort by timestamp
    events.sort(key=lambda e: e.get("timestamp", ""))
    return events


if __name__ == "__main__":
    import os
    out_path = os.path.join(os.path.dirname(__file__), "data", "demo", "sample_eve.json")
    os.makedirs(os.path.dirname(out_path), exist_ok=True)
    events = generate_events()
    with open(out_path, "w", encoding="utf-8") as f:
        for ev in events:
            f.write(json.dumps(ev) + "\n")
        # Add a deliberately malformed line to test parser resilience
        f.write("THIS IS NOT JSON AND SHOULD BE SKIPPED BY THE PARSER\n")
        f.write("{\"incomplete\": true\n")  # truncated JSON
    print(f"Generated {len(events)} events -> {out_path}")
