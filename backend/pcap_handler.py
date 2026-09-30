"""
PCAP upload handler.
Validates uploads and stores them safely in the configured uploads directory.
Does NOT execute Suricata; this is an offline workflow explained clearly in the UI.
"""

import hashlib
import logging
import os
from datetime import datetime

from werkzeug.utils import secure_filename

logger = logging.getLogger(__name__)

ALLOWED_EXTENSIONS = {".pcap", ".pcapng"}


class PcapError(ValueError):
    pass


def handle_upload(file_storage, upload_folder: str, max_size_bytes: int) -> dict:
    """
    Validate and save an uploaded PCAP file.

    Args:
        file_storage:   Flask's FileStorage object.
        upload_folder:  Absolute path to the upload directory.
        max_size_bytes: Maximum allowed file size in bytes.

    Returns:
        dict with file metadata.

    Raises:
        PcapError: on invalid input.
    """
    if not file_storage or file_storage.filename == "":
        raise PcapError("No file selected.")

    original_name = file_storage.filename or ""
    _, ext = os.path.splitext(original_name)
    if ext.lower() not in ALLOWED_EXTENSIONS:
        raise PcapError(f"Invalid file type '{ext}'. Only .pcap and .pcapng are accepted.")

    # Sanitize filename to prevent path traversal
    safe_name = secure_filename(original_name)
    if not safe_name:
        safe_name = "upload" + ext

    # Read content to check size (Werkzeug streams may not report size early)
    content = file_storage.read()
    if len(content) == 0:
        raise PcapError("Uploaded file is empty.")
    if len(content) > max_size_bytes:
        raise PcapError(
            f"File too large ({len(content) // 1024 // 1024} MB). "
            f"Maximum is {max_size_bytes // 1024 // 1024} MB."
        )

    os.makedirs(upload_folder, exist_ok=True)

    # Add timestamp prefix to avoid collisions
    ts = datetime.utcnow().strftime("%Y%m%d_%H%M%S")
    stored_name = f"{ts}_{safe_name}"
    dest_path = os.path.join(upload_folder, stored_name)

    # Final path-traversal check
    dest_real = os.path.realpath(dest_path)
    folder_real = os.path.realpath(upload_folder)
    if not dest_real.startswith(folder_real + os.sep):
        raise PcapError("Path traversal detected. Upload rejected.")

    with open(dest_path, "wb") as fh:
        fh.write(content)

    sha256 = hashlib.sha256(content).hexdigest()

    return {
        "filename": stored_name,
        "original_name": original_name,
        "size_bytes": len(content),
        "sha256": sha256,
        "uploaded_at": datetime.utcnow().isoformat() + "Z",
        "status": "uploaded",
        "analysis": "pending_offline",
        "note": (
            "File stored. To analyse: run Suricata offline against this PCAP, "
            "copy the resulting eve.json to the configured path, then set "
            "DATA_MODE=suricata and restart the dashboard."
        ),
    }


def list_uploads(upload_folder: str) -> list[dict]:
    """List uploaded PCAP files with basic metadata."""
    if not os.path.isdir(upload_folder):
        return []
    items = []
    for name in sorted(os.listdir(upload_folder), reverse=True):
        if os.path.splitext(name)[1].lower() not in ALLOWED_EXTENSIONS:
            continue
        path = os.path.join(upload_folder, name)
        stat = os.stat(path)
        items.append({
            "filename": name,
            "size_bytes": stat.st_size,
            "uploaded_at": datetime.utcfromtimestamp(stat.st_mtime).isoformat() + "Z",
            "status": "stored",
            "analysis": "pending_offline",
        })
    return items
