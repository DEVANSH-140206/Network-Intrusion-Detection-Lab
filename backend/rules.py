"""
Detection rules reader.
Parses Suricata .rules files (Snort/Suricata format) for display.
If no real rules file is configured, returns a demo ruleset clearly labelled DEMO.
"""

import logging
import os
import re
from typing import Optional

logger = logging.getLogger(__name__)

# ── Demo ruleset (shown when no real rules file is configured) ─────────────────
DEMO_RULES = [
    {"sid": 2010936, "gid": 1, "signature": "ET SCAN Nmap SYN Scan Detected", "category": "Attempted Information Leak", "severity": 2, "protocol": "tcp", "enabled": True},
    {"sid": 2010937, "gid": 1, "signature": "ET SCAN Nmap Version Scan Detected", "category": "Attempted Information Leak", "severity": 2, "protocol": "tcp", "enabled": True},
    {"sid": 2010050, "gid": 1, "signature": "ET SCAN Nmap OS Detection Probe", "category": "Attempted Information Leak", "severity": 2, "protocol": "tcp", "enabled": True},
    {"sid": 2010935, "gid": 1, "signature": "ET SCAN Nmap Scripting Engine User-Agent Detected", "category": "Attempted Information Leak", "severity": 2, "protocol": "tcp", "enabled": True},
    {"sid": 2001978, "gid": 1, "signature": "ET SCAN Shellcode Exploit Attempt", "category": "Attempted User Privilege Gain", "severity": 1, "protocol": "tcp", "enabled": True},
    {"sid": 2019284, "gid": 1, "signature": "ET EXPLOIT MS17-010 EternalBlue SMB Remote Windows Code Execution", "category": "Attempted User Privilege Gain", "severity": 1, "protocol": "tcp", "enabled": True},
    {"sid": 2013504, "gid": 1, "signature": "ET EXPLOIT vsftpd 2.3.4 Backdoor Command Execution", "category": "Attempted User Privilege Gain", "severity": 1, "protocol": "tcp", "enabled": True},
    {"sid": 2024987, "gid": 1, "signature": "ET MALWARE Meterpreter or Metasploit Framework Stager", "category": "A Network Trojan was Detected", "severity": 1, "protocol": "tcp", "enabled": True},
    {"sid": 2001876, "gid": 1, "signature": "ET TROJAN Metasploit Meterpreter reverse shell", "category": "A Network Trojan was Detected", "severity": 1, "protocol": "tcp", "enabled": True},
    {"sid": 2012887, "gid": 1, "signature": "ET POLICY ICMP Flood", "category": "Denial of Service", "severity": 2, "protocol": "icmp", "enabled": True},
    {"sid": 2014701, "gid": 1, "signature": "ET DOS Possible Slow HTTP DoS Attack (in progress)", "category": "Denial of Service", "severity": 2, "protocol": "tcp", "enabled": True},
    {"sid": 2000537, "gid": 1, "signature": "ET SCAN Potential SSH Scan", "category": "Attempted Information Leak", "severity": 2, "protocol": "tcp", "enabled": True},
    {"sid": 2009358, "gid": 1, "signature": "ET SCAN Suspicious inbound to mySQL port 3306", "category": "Potentially Bad Traffic", "severity": 2, "protocol": "tcp", "enabled": True},
    {"sid": 2100498, "gid": 1, "signature": "GPL ATTACK_RESPONSE id check returned root", "category": "Potentially Bad Traffic", "severity": 2, "protocol": "tcp", "enabled": True},
    {"sid": 2008446, "gid": 1, "signature": "ET POLICY Telnet Login Incorrect", "category": "Potentially Bad Traffic", "severity": 3, "protocol": "tcp", "enabled": False},
]

_RULE_RE = re.compile(
    r'(?P<action>\w+)\s+(?P<proto>\w+)\s+.*?'
    r'msg:"(?P<msg>[^"]+)".*?'
    r'sid:(?P<sid>\d+).*?'
    r'(?:gid:(?P<gid>\d+))?',
    re.DOTALL,
)


def load_rules(rules_path: Optional[str] = None) -> tuple[list[dict], bool]:
    """
    Load Suricata rules.

    Returns:
        (rules_list, is_demo)
    """
    if not rules_path or not os.path.isfile(rules_path):
        return DEMO_RULES, True

    rules = []
    try:
        with open(rules_path, "r", encoding="utf-8", errors="replace") as fh:
            for line in fh:
                line = line.strip()
                if not line or line.startswith("#"):
                    continue
                enabled = not line.startswith("#")
                # Remove leading '#' for disabled rules
                clean = line.lstrip("#").strip()
                m = _RULE_RE.search(clean)
                if m:
                    rules.append({
                        "sid": int(m.group("sid")),
                        "gid": int(m.group("gid") or 1),
                        "signature": m.group("msg"),
                        "category": "",
                        "severity": 3,
                        "protocol": m.group("proto"),
                        "enabled": enabled,
                    })
    except OSError as exc:
        logger.error("Cannot read rules file %s: %s", rules_path, exc)
        return DEMO_RULES, True

    if not rules:
        return DEMO_RULES, True

    return rules, False
