"""
Configuration module for the NIDS/SOC Flask Dashboard.
Reads settings from environment variables (or .env file via python-dotenv).
"""

import os
from dotenv import load_dotenv

# Load .env file if it exists
load_dotenv()


class Config:
    """Application configuration loaded from environment variables."""

    # Flask
    SECRET_KEY = os.getenv("SECRET_KEY", "change-me-in-production-please")
    DEBUG = os.getenv("FLASK_DEBUG", "false").lower() == "true"
    HOST = os.getenv("FLASK_HOST", "127.0.0.1")
    PORT = int(os.getenv("FLASK_PORT", "5000"))

    # Data mode: "demo" or "suricata"
    DATA_MODE = os.getenv("DATA_MODE", "demo").lower()

    # Suricata integration (only used when DATA_MODE=suricata)
    SURICATA_EVE_PATH = os.getenv("SURICATA_EVE_PATH", "")
    SURICATA_BIN = os.getenv("SURICATA_BIN", "")
    SURICATA_CONFIG = os.getenv("SURICATA_CONFIG", "")

    # PCAP uploads
    UPLOAD_FOLDER = os.getenv("UPLOAD_FOLDER", os.path.join(os.path.dirname(__file__), "data", "uploads"))
    MAX_PCAP_SIZE_MB = int(os.getenv("MAX_PCAP_SIZE_MB", "50"))

    # Demo data path
    DEMO_EVE_PATH = os.path.join(os.path.dirname(__file__), "data", "demo", "sample_eve.json")

    @classmethod
    def is_demo(cls) -> bool:
        return cls.DATA_MODE == "demo"

    @classmethod
    def active_eve_path(cls) -> str:
        """Return the eve.json path to use based on DATA_MODE."""
        if cls.is_demo():
            return cls.DEMO_EVE_PATH
        return cls.SURICATA_EVE_PATH
