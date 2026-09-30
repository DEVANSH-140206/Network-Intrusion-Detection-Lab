"""
Automated tests for the NIDS SOC Dashboard.

Run with:
    pytest tests/ -v
"""

import json
import os
import tempfile
import pytest

# ── Import backend modules ──────────────────────────────────────────────────────
from backend.parser import parse_eve_file, _severity_label
from backend import store
from app import create_app


# ─────────────────────────────────────────────────────────────────────────────
# Parser Tests
# ─────────────────────────────────────────────────────────────────────────────

class TestSeverityLabel:
    def test_critical(self):   assert _severity_label(1) == "Critical"
    def test_high(self):       assert _severity_label(2) == "High"
    def test_medium(self):     assert _severity_label(3) == "Medium"
    def test_low_default(self):assert _severity_label(4) == "Low"
    def test_unknown(self):    assert _severity_label(99) == "Low"


class TestParseEveFile:

    def _write_eve(self, lines: list) -> str:
        """Write lines to a temp file and return its path."""
        fd, path = tempfile.mkstemp(suffix=".json")
        with os.fdopen(fd, "w", encoding="utf-8") as f:
            for line in lines:
                if isinstance(line, dict):
                    f.write(json.dumps(line) + "\n")
                else:
                    f.write(line + "\n")
        return path

    def test_empty_path(self):
        alerts, meta = parse_eve_file("")
        assert alerts == []
        assert meta["file_exists"] is False

    def test_missing_file(self):
        alerts, meta = parse_eve_file("/nonexistent/path/eve.json")
        assert alerts == []
        assert meta["file_exists"] is False

    def test_valid_alert(self):
        event = {
            "timestamp": "2026-09-29T10:00:00.000+0530",
            "event_type": "alert",
            "src_ip": "192.168.56.101",
            "src_port": 45678,
            "dest_ip": "192.168.56.110",
            "dest_port": 22,
            "proto": "TCP",
            "flow_id": 123456,
            "alert": {
                "signature": "ET SCAN Nmap SYN Scan Detected",
                "category": "Attempted Information Leak",
                "severity": 2,
                "signature_id": 2010936,
                "gid": 1,
                "action": "allowed",
            }
        }
        path = self._write_eve([event])
        try:
            alerts, meta = parse_eve_file(path)
            assert len(alerts) == 1
            a = alerts[0]
            assert a["src_ip"] == "192.168.56.101"
            assert a["dest_ip"] == "192.168.56.110"
            assert a["severity"] == 2
            assert a["severity_label"] == "High"
            assert a["sid"] == 2010936
            assert a["proto"] == "TCP"
            assert meta["alert_lines"] == 1
            assert meta["skipped_malformed"] == 0
        finally:
            os.unlink(path)

    def test_skips_non_alert_events(self):
        events = [
            {"timestamp": "2026-09-29T10:00:00.000+0530", "event_type": "stats", "uptime": 100},
            {"timestamp": "2026-09-29T10:00:01.000+0530", "event_type": "flow",
             "src_ip": "1.2.3.4", "flow": {}},
            {"timestamp": "2026-09-29T10:00:02.000+0530", "event_type": "alert",
             "src_ip": "192.168.56.101", "dest_ip": "192.168.56.110",
             "proto": "TCP", "src_port": 1000, "dest_port": 80,
             "alert": {"signature": "Test", "category": "Test", "severity": 3,
                       "signature_id": 1, "gid": 1}},
        ]
        path = self._write_eve(events)
        try:
            alerts, meta = parse_eve_file(path)
            assert len(alerts) == 1
            assert meta["skipped_non_alert"] == 2
        finally:
            os.unlink(path)

    def test_malformed_lines_skipped(self):
        path = self._write_eve([
            "THIS IS NOT JSON",
            '{"truncated": true',
            {"timestamp": "2026-09-29T10:00:00.000+0530", "event_type": "alert",
             "src_ip": "10.0.0.1", "dest_ip": "10.0.0.2", "proto": "UDP",
             "src_port": 0, "dest_port": 0,
             "alert": {"signature": "Valid", "category": "Test", "severity": 4,
                       "signature_id": 999, "gid": 1}},
        ])
        try:
            alerts, meta = parse_eve_file(path)
            assert len(alerts) == 1
            assert meta["skipped_malformed"] == 2
        finally:
            os.unlink(path)

    def test_missing_fields_handled(self):
        """An alert with minimal fields should not crash the parser."""
        event = {
            "event_type": "alert",
            "alert": {"severity": 1, "signature_id": 42, "gid": 1},
        }
        path = self._write_eve([event])
        try:
            alerts, meta = parse_eve_file(path)
            assert len(alerts) == 1
            a = alerts[0]
            assert a["src_ip"] == ""
            assert a["dest_ip"] == ""
            assert a["proto"] == ""
            assert a["timestamp"] == ""
        finally:
            os.unlink(path)

    def test_alerts_sorted_newest_first(self):
        events = [
            {"timestamp": "2026-09-29T08:00:00.000+0530", "event_type": "alert",
             "alert": {"severity": 3, "signature_id": 1, "gid": 1}},
            {"timestamp": "2026-09-29T12:00:00.000+0530", "event_type": "alert",
             "alert": {"severity": 3, "signature_id": 2, "gid": 1}},
            {"timestamp": "2026-09-29T06:00:00.000+0530", "event_type": "alert",
             "alert": {"severity": 3, "signature_id": 3, "gid": 1}},
        ]
        path = self._write_eve(events)
        try:
            alerts, _ = parse_eve_file(path)
            timestamps = [a["timestamp"] for a in alerts]
            assert timestamps == sorted(timestamps, reverse=True)
        finally:
            os.unlink(path)

    def test_demo_data_parses_successfully(self):
        """The bundled demo data file must parse without errors."""
        demo_path = os.path.join(
            os.path.dirname(os.path.dirname(__file__)),
            "data", "demo", "sample_eve.json"
        )
        if not os.path.exists(demo_path):
            pytest.skip("Demo data file not generated yet")
        alerts, meta = parse_eve_file(demo_path)
        assert len(alerts) > 0
        assert meta["file_readable"] is True
        # Malformed lines in demo file should not cause crashes
        assert len(alerts) == meta["alert_lines"]


# ─────────────────────────────────────────────────────────────────────────────
# Flask API Tests
# ─────────────────────────────────────────────────────────────────────────────

@pytest.fixture(scope="module")
def client():
    """Flask test client using demo data."""
    os.environ["DATA_MODE"] = "demo"
    app = create_app()
    app.config["TESTING"] = True
    with app.test_client() as c:
        yield c


class TestHealthEndpoint:
    def test_health_returns_200(self, client):
        r = client.get("/api/health")
        assert r.status_code == 200

    def test_health_has_status(self, client):
        data = r = client.get("/api/health").get_json()
        assert data["status"] == "ok"
        assert "data_mode" in data


class TestStatsEndpoint:
    def test_stats_200(self, client):
        assert client.get("/api/stats").status_code == 200

    def test_stats_structure(self, client):
        data = client.get("/api/stats").get_json()
        for key in ("total_alerts", "critical", "high", "medium", "low",
                    "events_today", "unique_src_ips", "unique_dest_ips"):
            assert key in data, f"Missing key: {key}"

    def test_stats_totals_consistent(self, client):
        data = client.get("/api/stats").get_json()
        sev_sum = data["critical"] + data["high"] + data["medium"] + data["low"]
        assert sev_sum == data["total_alerts"]


class TestAlertsEndpoint:
    def test_alerts_200(self, client):
        assert client.get("/api/alerts").status_code == 200

    def test_alerts_structure(self, client):
        data = client.get("/api/alerts").get_json()
        for key in ("alerts", "total", "page", "per_page", "total_pages"):
            assert key in data

    def test_pagination_works(self, client):
        data = client.get("/api/alerts?page=1&per_page=5").get_json()
        assert len(data["alerts"]) <= 5
        assert data["per_page"] == 5

    def test_search_filter(self, client):
        data = client.get("/api/alerts?search=Nmap").get_json()
        for a in data["alerts"]:
            assert "nmap" in a["signature"].lower() or "nmap" in a["category"].lower()

    def test_severity_filter(self, client):
        data = client.get("/api/alerts?severity=critical").get_json()
        for a in data["alerts"]:
            assert a["severity"] == 1

    def test_invalid_per_page_clamped(self, client):
        data = client.get("/api/alerts?per_page=9999").get_json()
        assert data["per_page"] <= 100

    def test_alert_detail_exists(self, client):
        # Get first alert then fetch its detail
        data = client.get("/api/alerts?per_page=1").get_json()
        if not data["alerts"]:
            pytest.skip("No alerts in demo data")
        alert_id = data["alerts"][0]["id"]
        r = client.get(f"/api/alerts/{alert_id}")
        assert r.status_code == 200
        detail = r.get_json()
        assert detail["id"] == alert_id
        assert "raw" in detail

    def test_alert_detail_404(self, client):
        r = client.get("/api/alerts/99999999")
        assert r.status_code == 404


class TestTimelineEndpoint:
    def test_timeline_200(self, client):
        assert client.get("/api/timeline").status_code == 200

    def test_timeline_sorted(self, client):
        data = client.get("/api/timeline").get_json()
        times = [d["time"] for d in data]
        assert times == sorted(times)


class TestProtocolsEndpoint:
    def test_protocols_200(self, client):
        r = client.get("/api/protocols")
        assert r.status_code == 200

    def test_protocols_have_percent(self, client):
        data = client.get("/api/protocols").get_json()
        for p in data:
            assert "percent" in p
            assert 0 <= p["percent"] <= 100


class TestRulesEndpoint:
    def test_rules_200(self, client):
        r = client.get("/api/rules")
        assert r.status_code == 200

    def test_rules_structure(self, client):
        data = client.get("/api/rules").get_json()
        assert "rules" in data
        assert "is_demo" in data
        assert isinstance(data["rules"], list)


class TestSystemStatusEndpoint:
    def test_status_200(self, client):
        assert client.get("/api/system-status").status_code == 200

    def test_status_has_components(self, client):
        data = client.get("/api/system-status").get_json()
        assert "components" in data
        assert len(data["components"]) > 0

    def test_flask_backend_is_online(self, client):
        data = client.get("/api/system-status").get_json()
        flask_comp = next((c for c in data["components"] if c["name"] == "Flask Backend"), None)
        assert flask_comp is not None
        assert flask_comp["status"] == "ONLINE"

    def test_demo_mode_simulation(self, client):
        data = client.get("/api/system-status").get_json()
        suricata = next((c for c in data["components"] if "Suricata" in c["name"]), None)
        assert suricata is not None
        assert "SIMULATION" in suricata["status"] or "NOT" in suricata["status"]


class TestFrontend:
    def test_index_returns_html(self, client):
        r = client.get("/")
        assert r.status_code == 200
        assert b"NIDS" in r.data or b"Dashboard" in r.data


class TestPcapList:
    def test_pcap_list_200(self, client):
        r = client.get("/api/pcap/list")
        assert r.status_code == 200
        data = r.get_json()
        assert "files" in data
        assert isinstance(data["files"], list)
