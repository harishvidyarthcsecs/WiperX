# wiperx/core/report_paths.py
"""
Report path helper
------------------
One place that decides where a certificate/report file lives and what it is
called, so every module (drive wipe, file erase, free-space wipe, recovery)
produces the same tidy, sortable layout:

    reports/<YYYY-MM-DD>/<kind>_<target-slug>_<HHMMSS>Z.json

`kind` is one of: wipe | erase | freespace | recover.
"""

from __future__ import annotations

import re
from datetime import datetime, timezone
from pathlib import Path
from typing import Optional, Union

REPORTS_DIR = Path(__file__).parent.parent / "reports"

_KINDS = ("wipe", "erase", "freespace", "recover")


def slug(value: str, *, max_len: int = 40) -> str:
    """Lowercase, keep [a-z0-9], collapse everything else to a single '-'."""
    s = re.sub(r"[^a-z0-9]+", "-", str(value).lower()).strip("-")
    return (s[:max_len].rstrip("-")) or "x"


def _as_dt(when: Union[datetime, str, None]) -> datetime:
    if isinstance(when, datetime):
        return when
    if isinstance(when, str) and when:
        raw = when.strip().replace("Z", "").replace("z", "")
        for fmt in ("%Y-%m-%dT%H:%M:%S.%f", "%Y-%m-%dT%H:%M:%S", "%Y-%m-%dT%H:%M",
                    "%Y%m%dT%H%M%S"):
            try:
                return datetime.strptime(raw, fmt)
            except ValueError:
                continue
    return datetime.now(timezone.utc)


def report_path(
    kind: str,
    target: str,
    *,
    when: Union[datetime, str, None] = None,
    ext: str = "json",
    subdir: bool = False,
    base_dir: Optional[Path] = None,
) -> Path:
    """
    Build (and create the parent of) a report path.

        reports/<date>/<kind>_<slug(target)>_<HHMMSS>Z[.ext]

    subdir=True returns a directory path (no extension) and makes it — used by
    recovery, whose "report" is a folder of recovered files + case_report.json.
    """
    if kind not in _KINDS:
        raise ValueError(f"unknown report kind: {kind!r} (expected one of {_KINDS})")

    dt = _as_dt(when)
    root = (base_dir or REPORTS_DIR) / dt.strftime("%Y-%m-%d")
    name = f"{kind}_{slug(target)}_{dt.strftime('%H%M%S')}Z"

    if subdir:
        out = root / name
        out.mkdir(parents=True, exist_ok=True)
        return out

    root.mkdir(parents=True, exist_ok=True)
    return root / f"{name}.{ext}"


def kind_of(name: str) -> str:
    """Best-effort report kind from a filename (new scheme or legacy *_cert_*)."""
    stem = Path(name).name
    first = stem.split("_", 1)[0].lower()
    if first in _KINDS:
        return first
    for k in _KINDS:
        if stem.startswith((f"{k}_cert_", f"{k}_report_", f"{k}-")):
            return k
    if stem == "case_report.json" or stem.startswith("case"):
        return "recover"
    return "other"
