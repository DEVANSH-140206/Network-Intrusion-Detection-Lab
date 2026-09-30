"""
Network Intrusion Detection Lab — SOC Dashboard
Flask application entry point.

Run:
    python app.py

Or with gunicorn (production):
    gunicorn -w 1 -b 127.0.0.1:5000 app:app
"""

import logging
import os

from flask import Flask, render_template, send_from_directory

from config import Config
from backend import store
from backend.routes import api

# ─── Logging ──────────────────────────────────────────────────────────────────
logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(name)s: %(message)s",
)
logger = logging.getLogger(__name__)


def create_app() -> Flask:
    app = Flask(
        __name__,
        template_folder="frontend/templates",
        static_folder="frontend/static",
    )

    # ── Configuration ─────────────────────────────────────────────────────────
    app.config["SECRET_KEY"] = Config.SECRET_KEY
    app.config["DATA_MODE"] = Config.DATA_MODE
    app.config["SURICATA_EVE_PATH"] = Config.SURICATA_EVE_PATH
    app.config["SURICATA_BIN"] = Config.SURICATA_BIN
    app.config["SURICATA_CONFIG"] = Config.SURICATA_CONFIG
    app.config["UPLOAD_FOLDER"] = Config.UPLOAD_FOLDER
    app.config["MAX_PCAP_SIZE_MB"] = Config.MAX_PCAP_SIZE_MB
    app.config["SURICATA_RULES_PATH"] = os.getenv("SURICATA_RULES_PATH", "")

    # ── Ensure upload directory exists ────────────────────────────────────────
    os.makedirs(Config.UPLOAD_FOLDER, exist_ok=True)

    # ── Load alert data ───────────────────────────────────────────────────────
    eve_path = Config.active_eve_path()
    logger.info("DATA_MODE=%s  EVE_PATH=%s", Config.DATA_MODE, eve_path or "(none)")
    store.load(eve_path)
    meta = store.get_parse_meta()
    logger.info(
        "Parser: %d alerts, %d malformed, %d skipped",
        meta.get("alert_lines", 0),
        meta.get("skipped_malformed", 0),
        meta.get("skipped_non_alert", 0),
    )

    # ── Register API blueprint ────────────────────────────────────────────────
    app.register_blueprint(api)

    # ── Frontend page routes ──────────────────────────────────────────────────
    # All pages are served from a single template; JS handles routing/sections.

    @app.route("/")
    def index():
        return render_template(
            "index.html",
            data_mode=Config.DATA_MODE,
            is_demo=Config.is_demo(),
        )

    # Catch-all so direct URL navigation still serves the SPA
    @app.route("/<path:path>")
    def catch_all(path):
        # Serve static files normally
        static_path = os.path.join(app.static_folder, path)
        if os.path.isfile(static_path):
            return send_from_directory(app.static_folder, path)
        return render_template(
            "index.html",
            data_mode=Config.DATA_MODE,
            is_demo=Config.is_demo(),
        )

    return app


app = create_app()

if __name__ == "__main__":
    logger.info("Starting NIDS Dashboard on http://%s:%d", Config.HOST, Config.PORT)
    app.run(host=Config.HOST, port=Config.PORT, debug=Config.DEBUG)
