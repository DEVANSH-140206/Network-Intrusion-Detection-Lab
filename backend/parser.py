"""
Eve.json parser.
Reads Suricata's eve.json file (one JSON object per line) and returns
a list of normalised alert dicts. Skips non-alert events and malformed lines.
"""

import json
import logging
import os
from typing import Optional

logger = logging.getLogger(__name__)


def _safe_int(value, default: int = 0) -> int:
    try:
        return int(value)
    except (TypeError, ValueError):
        return default


def parse_eve_file(path: str) -> tuple[list[dict], dict]:
    """
    Parse a Suricata eve.json file.

    Returns:
        (alerts, meta) where:
          - alerts  is a list of normalised alert dicts (sorted by timestamp)
          - meta    is a dict with parsing statistics
    """
    alerts = []
    meta = {
        "total_lines": 0,
        "alert_lines": 0,
        "skipped_non_alert": 0,
        "skipped_malformed": 0,
        "file_path": path,
        "file_exists": False,
        "file_readable": False,
    }

    if not path:
        return alerts, meta

    if not os.path.exists(path):
        logger.warning("eve.json not found: %s", path)
        return alerts, meta

    meta["file_exists"] = True

    try:
        with open(path, "r", encoding="utf-8", errors="replace") as fh:
            for line_num, raw in enumerate(fh, start=1):
                meta["total_lines"] += 1
                raw = raw.strip()
                if not raw:
                    continue

                try:
                    obj = json.loads(raw)
                except json.JSONDecodeError:
                    meta["skipped_malformed"] += 1
                    logger.debug("Malformed JSON on line %d in %s", line_num, path)
                    continue

                if not isinstance(obj, dict):
                    meta["skipped_malformed"] += 1
                    continue

                if obj.get("event_type") != "alert":
                    meta["skipped_non_alert"] += 1
                    continue

                alert_block = obj.get("alert", {})
                if not isinstance(alert_block, dict):
                    meta["skipped_malformed"] += 1
                    continue

                severity_raw = alert_block.get("severity", 4)
                severity = _safe_int(severity_raw, 4)

                alert = {
                    # Identity
                    "id": len(alerts) + 1,
                    # Timestamps
                    "timestamp": obj.get("timestamp", ""),
                    "timestamp_raw": obj.get("timestamp", ""),
                    # Network
                    "src_ip": obj.get("src_ip", ""),
                    "src_port": _safe_int(obj.get("src_port"), 0),
                    "dest_ip": obj.get("dest_ip", ""),
                    "dest_port": _safe_int(obj.get("dest_port"), 0),
                    "proto": (obj.get("proto") or "").upper(),
                    # Flow
                    "flow_id": obj.get("flow_id", ""),
                    # Alert details
                    "signature": alert_block.get("signature", "Unknown Signature"),
                    "category": alert_block.get("category", "Unknown"),
                    "severity": severity,
                    "severity_label": _severity_label(severity),
                    "action": alert_block.get("action", ""),
                    "sid": _safe_int(alert_block.get("signature_id"), 0),
                    "gid": _safe_int(alert_block.get("gid"), 1),
                    "rev": _safe_int(alert_block.get("rev"), 0),
                    # Raw JSON for the details view
                    "raw": json.dumps(obj, indent=2),
                }
                alerts.append(alert)
                meta["alert_lines"] += 1

        meta["file_readable"] = True
    except OSError as exc:
        logger.error("Cannot read %s: %s", path, exc)

    # Stable sort: newest first
    alerts.sort(key=lambda a: a["timestamp"], reverse=True)
    # Re-assign sequential IDs after sort
    for idx, a in enumerate(alerts, start=1):
        a["id"] = idx

    return alerts, meta


def _severity_label(severity: int) -> str:
    return {1: "Critical", 2: "High", 3: "Medium"}.get(severity, "Low")
