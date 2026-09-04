# wiperx/core/timeutils.py
"""
UTC time helpers
----------------
One place for timezone-aware UTC timestamps so every report, certificate and
log line uses the same format. Replaces the deprecated ``datetime.utcnow()``
(removed in a future Python) while keeping the trailing ``Z`` the rest of the
codebase and its tests expect.
"""

from __future__ import annotations

from datetime import datetime, timezone


def utc_now() -> datetime:
    """Timezone-aware current UTC time."""
    return datetime.now(timezone.utc)


def utc_iso() -> str:
    """ISO-8601 UTC timestamp ending in 'Z', e.g. 2026-09-04T06:14:31.101363Z."""
    return utc_now().strftime("%Y-%m-%dT%H:%M:%S.%f") + "Z"


def utc_stamp() -> str:
    """Compact UTC stamp for filenames, e.g. 20260904T061431Z."""
    return utc_now().strftime("%Y%m%dT%H%M%SZ")
