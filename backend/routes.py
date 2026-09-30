"""
Flask API routes for the NIDS/SOC Dashboard.
All endpoints return JSON. The frontend fetches data exclusively from here.
"""

import logging

from flask import Blueprint, jsonify, request, current_app

from backend import store
from backend.pcap_handler import PcapError, handle_upload, list_uploads
from backend.rules import load_rules

logger = logging.getLogger(__name__)

api = Blueprint("api", __name__, url_prefix="/api")


# ─── Health ────────────────────────────────────────────────────────────────────

@api.route("/health")
def health():
    return jsonify({"status": "ok", "data_mode": current_app.config["DATA_MODE"]})


# ─── Alerts ───────────────────────────────────────────────────────────────────

@api.route("/alerts")
def alerts():
    """
    Paginated, filtered, sorted alerts.

    Query params:
      search, severity, category, protocol, src_ip, dest_ip,
      sort_by, sort_order, page, per_page
    """
    result = store.get_alerts(
        search=request.args.get("search", "").strip() or None,
        severity=request.args.get("severity", "").strip() or None,
        category=request.args.get("category", "").strip() or None,
        protocol=request.args.get("protocol", "").strip() or None,
        src_ip=request.args.get("src_ip", "").strip() or None,
        dest_ip=request.args.get("dest_ip", "").strip() or None,
        sort_by=request.args.get("sort_by", "timestamp"),
        sort_order=request.args.get("sort_order", "desc"),
        page=max(1, _int_param("page", 1)),
        per_page=min(100, max(1, _int_param("per_page", 25))),
    )
    return jsonify(result)


@api.route("/alerts/<int:alert_id>")
def alert_detail(alert_id: int):
    alert = store.get_alert_by_id(alert_id)
    if alert is None:
        return jsonify({"error": "Alert not found"}), 404
    return jsonify(alert)


# ─── Statistics ───────────────────────────────────────────────────────────────

@api.route("/stats")
def stats():
    data = store.get_stats()
    data["data_mode"] = current_app.config["DATA_MODE"]
    data["is_demo"] = current_app.config["DATA_MODE"] == "demo"
    return jsonify(data)


@api.route("/timeline")
def timeline():
    bucket = request.args.get("bucket", "hour")
    if bucket not in ("hour", "day"):
        bucket = "hour"
    return jsonify(store.get_timeline(bucket))


@api.route("/top-sources")
def top_sources():
    limit = min(20, max(1, _int_param("limit", 10)))
    return jsonify(store.get_top_sources(limit))


@api.route("/top-destinations")
def top_destinations():
    limit = min(20, max(1, _int_param("limit", 10)))
    return jsonify(store.get_top_destinations(limit))


@api.route("/protocols")
def protocols():
    return jsonify(store.get_protocols())


@api.route("/categories")
def categories():
    return jsonify(store.get_categories())


@api.route("/top-dest-ports")
def top_dest_ports():
    limit = min(20, max(1, _int_param("limit", 10)))
    return jsonify(store.get_top_dest_ports(limit))


@api.route("/top-src-ports")
def top_src_ports():
    limit = min(20, max(1, _int_param("limit", 10)))
    return jsonify(store.get_top_src_ports(limit))


@api.route("/flow-pairs")
def flow_pairs():
    limit = min(50, max(1, _int_param("limit", 15)))
    return jsonify(store.get_flow_pairs(limit))


@api.route("/filter-options")
def filter_options():
    return jsonify({
        "categories": store.get_unique_categories(),
        "protocols": store.get_unique_protocols(),
    })


# ─── Rules ────────────────────────────────────────────────────────────────────

@api.route("/rules")
def rules():
    rules_path = current_app.config.get("SURICATA_RULES_PATH", "")
    rule_list, is_demo = load_rules(rules_path or None)
    return jsonify({"rules": rule_list, "is_demo": is_demo, "total": len(rule_list)})


# ─── System Status ────────────────────────────────────────────────────────────

@api.route("/system-status")
def system_status():
    cfg = current_app.config
    eve_path = cfg.get("SURICATA_EVE_PATH", "")
    demo_mode = cfg["DATA_MODE"] == "demo"
    meta = store.get_parse_meta()

    def suricata_status():
        if demo_mode:
            return "SIMULATION MODE"
        if not eve_path:
            return "NOT CONFIGURED"
        if not meta.get("file_exists"):
            return "OFFLINE"
        if not meta.get("file_readable"):
            return "ERROR"
        return "ONLINE (FILE SOURCE)"

    components = [
        {
            "name": "Flask Backend",
            "role": "Dashboard API & Web Server",
            "status": "ONLINE",
            "detail": "Running and serving requests",
        },
        {
            "name": "Suricata IDS",
            "role": "Network Intrusion Detection Sensor",
            "status": suricata_status(),
            "detail": (
                f"Reading: {eve_path}" if not demo_mode and eve_path
                else "Using bundled demo dataset"
            ),
        },
        {
            "name": "Data Source",
            "role": "Eve.json Alert Feed",
            "status": "SIMULATION MODE" if demo_mode else ("ONLINE" if meta.get("file_readable") else "NOT CONNECTED"),
            "detail": (
                f"Demo dataset: {meta.get('alert_lines', 0)} alerts loaded"
                if demo_mode
                else f"Real eve.json: {meta.get('alert_lines', 0)} alerts loaded"
            ),
        },
        {
            "name": "Kali Linux",
            "role": "Attack / Reconnaissance Machine",
            "status": "UNKNOWN",
            "detail": "Dashboard cannot verify VM connectivity — check VirtualBox",
        },
        {
            "name": "Metasploitable2",
            "role": "Vulnerable Target Server",
            "status": "UNKNOWN",
            "detail": "Dashboard cannot verify VM connectivity — check VirtualBox",
        },
        {
            "name": "Wireshark",
            "role": "Packet Capture & Traffic Analysis",
            "status": "UNKNOWN",
            "detail": "Dashboard cannot verify Wireshark state — use manually",
        },
        {
            "name": "PCAP Analysis",
            "role": "Offline PCAP Processing",
            "status": "OFFLINE WORKFLOW",
            "detail": "Upload .pcap/.pcapng → run Suricata offline → import eve.json",
        },
    ]

    return jsonify({"components": components, "data_mode": cfg["DATA_MODE"]})


# ─── PCAP ─────────────────────────────────────────────────────────────────────

@api.route("/pcap/upload", methods=["POST"])
def pcap_upload():
    file = request.files.get("pcap")
    try:
        upload_folder = current_app.config["UPLOAD_FOLDER"]
        max_bytes = current_app.config["MAX_PCAP_SIZE_MB"] * 1024 * 1024
        info = handle_upload(file, upload_folder, max_bytes)
        return jsonify(info), 201
    except PcapError as exc:
        return jsonify({"error": str(exc)}), 400


@api.route("/pcap/list")
def pcap_list():
    upload_folder = current_app.config["UPLOAD_FOLDER"]
    return jsonify({"files": list_uploads(upload_folder)})


# ─── Helpers ──────────────────────────────────────────────────────────────────

def _int_param(name: str, default: int) -> int:
    try:
        return int(request.args.get(name, default))
    except (TypeError, ValueError):
        return default
