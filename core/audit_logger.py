# wiperx/core/audit_logger.py
"""
Audit Logger
------------
Structured logging for all WiperX operations.
Every command executed, every wipe initiated, every access attempt
is recorded in a tamper-evident JSON log file.

Log format: JSON Lines (one JSON object per line) for easy parsing.
Log location: /logs/wiperx_audit_<date>.log

In a production deployment, these logs should be:
  - Sent to a centralized SIEM (Splunk, ELK, etc.) — done, see
    core/siem_forwarder.py; disabled unless a target is configured.
  - Stored on immutable storage (write-once S3, WORM disks)
  - Signed with HMAC to detect tampering
"""

import json
import logging
import os
import socket
import getpass
from datetime import datetime
from pathlib import Path

from core import siem_forwarder

LOGS_DIR = Path(__file__).parent.parent / "logs"
LOGS_DIR.mkdir(exist_ok=True)


def _safe_getuser() -> str:
    try:
        return getpass.getuser()
    except Exception:
        return "unknown"


def get_audit_logger() -> logging.Logger:
    """
    Configure and return a structured JSON audit logger.
    Creates a new log file per day.

    Returns:
        logging.Logger: Configured audit logger.
    """
    today = datetime.utcnow().strftime("%Y-%m-%d")
    log_file = LOGS_DIR / f"wiperx_audit_{today}.log"

    logger = logging.getLogger("wiperx.audit")
    logger.setLevel(logging.INFO)

    # Avoid adding duplicate handlers
    if logger.handlers:
        return logger

    # File handler — JSON Lines format
    file_handler = logging.FileHandler(log_file, encoding="utf-8")
    file_handler.setLevel(logging.INFO)

    class JsonFormatter(logging.Formatter):
        def format(self, record):
            log_entry = {
                "timestamp": datetime.utcnow().isoformat() + "Z",
                "level": record.levelname,
                "event": record.getMessage(),
                "module": record.module,
                "host": socket.gethostname(),
                "user": _safe_getuser(),
                "pid": os.getpid(),
            }
            if hasattr(record, "extra_data"):
                log_entry["data"] = record.extra_data
            return json.dumps(log_entry)

    file_handler.setFormatter(JsonFormatter())
    logger.addHandler(file_handler)

    # Also output to console for CLI visibility
    console_handler = logging.StreamHandler()
    console_handler.setLevel(logging.WARNING)
    logger.addHandler(console_handler)

    return logger


def log_event(event: str, data: dict = None):
    """
    Log an audit event with optional structured data.

    Also best-effort forwarded to a SIEM target if one is configured (see
    core/siem_forwarder.py) - non-blocking, and a no-op when none is set.

    Args:
        event : Description of the event.
        data  : Optional dictionary of event-specific data.
    """
    audit_logger = get_audit_logger()
    record = logging.LogRecord(
        name="wiperx.audit",
        level=logging.INFO,
        pathname="",
        lineno=0,
        msg=event,
        args=(),
        exc_info=None,
    )
    if data:
        record.extra_data = data
    audit_logger.handle(record)

    if siem_forwarder.is_configured():
        entry = {
            "timestamp": datetime.utcnow().isoformat() + "Z",
            "level": "INFO",
            "event": event,
            "module": "audit_logger",
            "host": socket.gethostname(),
            "user": _safe_getuser(),
            "pid": os.getpid(),
        }
        if data:
            entry["data"] = data
        siem_forwarder.forward_event(entry)


def read_recent_events(limit: int = 20) -> list:
    """
    Return the most recent audit events (newest first) from the latest log file.

    Reads only the current day's ``wiperx_audit_<date>.log``; malformed lines
    are skipped. Returns an empty list if no log file exists yet.

    Args:
        limit : Maximum number of events to return.

    Returns:
        list[dict] : parsed JSON-Lines records, newest first.
    """
    files = sorted(LOGS_DIR.glob("wiperx_audit_*.log"))
    if not files:
        return []
    try:
        lines = files[-1].read_text(encoding="utf-8", errors="replace").splitlines()
    except OSError:
        return []

    events = []
    for line in lines[-max(1, limit):]:
        line = line.strip()
        if not line:
            continue
        try:
            events.append(json.loads(line))
        except ValueError:
            continue
    events.reverse()
    return events
