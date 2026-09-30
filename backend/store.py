"""
In-memory data store.
Holds parsed alerts and provides query helpers used by the API routes.
All filtering, sorting, and pagination happens here so routes stay thin.
"""

import logging
import os
import re
from collections import Counter, defaultdict
from datetime import datetime, timezone
from typing import Optional

from backend.parser import parse_eve_file

logger = logging.getLogger(__name__)

# ─── Cached state ──────────────────────────────────────────────────────────────
_alerts: list[dict] = []
_parse_meta: dict = {}
_loaded: bool = False


def load(eve_path: str) -> None:
    """Parse the eve.json file and cache results."""
    global _alerts, _parse_meta, _loaded
    _alerts, _parse_meta = parse_eve_file(eve_path)
    _loaded = True
    logger.info("Loaded %d alerts from %s", len(_alerts), eve_path or "(none)")


def reload(eve_path: str) -> None:
    """Force a reload from disk."""
    global _loaded
    _loaded = False
    load(eve_path)


def get_parse_meta() -> dict:
    return dict(_parse_meta)


# ─── Query helpers ─────────────────────────────────────────────────────────────

def get_alerts(
    search: Optional[str] = None,
    severity: Optional[str] = None,
    category: Optional[str] = None,
    protocol: Optional[str] = None,
    src_ip: Optional[str] = None,
    dest_ip: Optional[str] = None,
    sort_by: str = "timestamp",
    sort_order: str = "desc",
    page: int = 1,
    per_page: int = 25,
) -> dict:
    """
    Return filtered, sorted, paginated alerts.
    All string comparisons are case-insensitive.
    """
    results = list(_alerts)

    # ── Search ────────────────────────────────────────────────────────────────
    if search:
        pattern = re.compile(re.escape(search), re.IGNORECASE)
        results = [
            a for a in results
            if pattern.search(a["signature"])
            or pattern.search(a["category"])
            or pattern.search(a["src_ip"])
            or pattern.search(a["dest_ip"])
            or pattern.search(str(a["sid"]))
        ]

    # ── Filters ───────────────────────────────────────────────────────────────
    if severity:
        sev_map = {"critical": 1, "high": 2, "medium": 3, "low": 4}
        sev_val = sev_map.get(severity.lower())
        if sev_val:
            results = [a for a in results if a["severity"] == sev_val]

    if category:
        results = [a for a in results if a["category"].lower() == category.lower()]

    if protocol:
        results = [a for a in results if a["proto"].lower() == protocol.lower()]

    if src_ip:
        results = [a for a in results if src_ip.strip() in a["src_ip"]]

    if dest_ip:
        results = [a for a in results if dest_ip.strip() in a["dest_ip"]]

    # ── Sort ──────────────────────────────────────────────────────────────────
    allowed_sorts = {"timestamp", "severity", "src_ip", "dest_ip", "proto", "signature", "sid"}
    if sort_by not in allowed_sorts:
        sort_by = "timestamp"
    reverse = sort_order.lower() != "asc"
    results.sort(key=lambda a: (a.get(sort_by) or ""), reverse=reverse)

    # ── Pagination ────────────────────────────────────────────────────────────
    total = len(results)
    start = (page - 1) * per_page
    end = start + per_page
    page_items = results[start:end]

    return {
        "alerts": page_items,
        "total": total,
        "page": page,
        "per_page": per_page,
        "total_pages": max(1, (total + per_page - 1) // per_page),
    }


def get_alert_by_id(alert_id: int) -> Optional[dict]:
    for a in _alerts:
        if a["id"] == alert_id:
            return a
    return None


def get_stats() -> dict:
    total = len(_alerts)
    sev_counts = Counter(a["severity_label"] for a in _alerts)
    today_str = datetime.now(timezone.utc).strftime("%Y-%m-%d")
    today_count = sum(1 for a in _alerts if a["timestamp"].startswith(today_str))

    return {
        "total_alerts": total,
        "critical": sev_counts.get("Critical", 0),
        "high": sev_counts.get("High", 0),
        "medium": sev_counts.get("Medium", 0),
        "low": sev_counts.get("Low", 0),
        "events_today": today_count,
        "unique_src_ips": len({a["src_ip"] for a in _alerts if a["src_ip"]}),
        "unique_dest_ips": len({a["dest_ip"] for a in _alerts if a["dest_ip"]}),
    }


def get_timeline(bucket: str = "hour") -> list[dict]:
    """
    Group alert counts by time bucket.
    bucket: 'hour' or 'day'
    Returns list of {time, count} sorted ascending.
    """
    buckets: Counter = Counter()
    for a in _alerts:
        ts = a["timestamp"]
        if not ts:
            continue
        try:
            # Normalise timezone offset formats
            ts_clean = ts.replace("+0530", "+05:30")
            if len(ts_clean) >= 16:
                if bucket == "day":
                    key = ts_clean[:10]
                else:
                    key = ts_clean[:13] + ":00"
                buckets[key] += 1
        except Exception:
            pass

    return [{"time": k, "count": v} for k, v in sorted(buckets.items())]


def get_top_sources(limit: int = 10) -> list[dict]:
    counts = Counter(a["src_ip"] for a in _alerts if a["src_ip"])
    return [{"ip": ip, "count": c} for ip, c in counts.most_common(limit)]


def get_top_destinations(limit: int = 10) -> list[dict]:
    counts = Counter(a["dest_ip"] for a in _alerts if a["dest_ip"])
    return [{"ip": ip, "count": c} for ip, c in counts.most_common(limit)]


def get_protocols() -> list[dict]:
    counts = Counter(a["proto"] for a in _alerts if a["proto"])
    total = sum(counts.values()) or 1
    return [
        {"protocol": p, "count": c, "percent": round(c / total * 100, 1)}
        for p, c in counts.most_common()
    ]


def get_categories() -> list[dict]:
    counts = Counter(a["category"] for a in _alerts if a["category"])
    return [{"category": cat, "count": c} for cat, c in counts.most_common()]


def get_top_dest_ports(limit: int = 10) -> list[dict]:
    counts = Counter(a["dest_port"] for a in _alerts if a["dest_port"])
    return [{"port": p, "count": c} for p, c in counts.most_common(limit)]


def get_top_src_ports(limit: int = 10) -> list[dict]:
    counts = Counter(a["src_port"] for a in _alerts if a["src_port"])
    return [{"port": p, "count": c} for p, c in counts.most_common(limit)]


def get_flow_pairs(limit: int = 15) -> list[dict]:
    """Source -> destination pairs by alert count."""
    pairs: Counter = Counter()
    for a in _alerts:
        if a["src_ip"] and a["dest_ip"]:
            pairs[(a["src_ip"], a["dest_ip"])] += 1
    return [
        {"src": src, "dest": dst, "count": c}
        for (src, dst), c in pairs.most_common(limit)
    ]


def get_unique_categories() -> list[str]:
    return sorted({a["category"] for a in _alerts if a["category"]})


def get_unique_protocols() -> list[str]:
    return sorted({a["proto"] for a in _alerts if a["proto"]})


def all_alerts() -> list[dict]:
    return list(_alerts)
