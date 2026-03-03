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
  - Sent to a centralized SIEM (Splunk, ELK, etc.)
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

LOGS_DIR = Path(__file__).parent.parent / "logs"
LOGS_DIR.mkdir(exist_ok=True)


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
                "user": self._safe_getuser(),
                "pid": os.getpid(),
            }
            if hasattr(record, "extra_data"):
                log_entry["data"] = record.extra_data
            return json.dumps(log_entry)

        @staticmethod
        def _safe_getuser():
            try:
                return getpass.getuser()
            except Exception:
                return "unknown"

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
