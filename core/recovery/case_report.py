# wiperx/core/recovery/case_report.py
"""
Forensic Case Report
--------------------
Assemble the machine-readable recovery report and write it as an
Ed25519-signed JSON certificate.

Determinism: the `files` array is sorted by (offset, seq) and a
`manifest_sha256` is computed over just that array (relative paths, no
timestamps) - the same source image produces the same manifest hash on
every run. `generated_at` and the signature naturally differ per run.
"""

from __future__ import annotations

import hashlib
import json
import logging
from collections import Counter
from datetime import datetime
from pathlib import Path
from typing import List, Tuple

logger = logging.getLogger(__name__)

SCHEMA_VERSION = "1.0"
COMPLIANCE_NOTE = (
    "Software recovery from a read-only source image/device. Recovered files "
    "are best-effort reconstructions; confidence scores estimate byte-fidelity. "
    "Source SHA-256 and per-file SHA-256 support chain-of-custody verification."
)


def _manifest_hash(files: List[dict]) -> str:
    stable = [
        {k: f[k] for k in (
            "seq", "offset", "end", "size", "sha256", "source_method",
            "signature", "category", "recovered_name", "validation_state",
        ) if k in f}
        for f in files
    ]
    blob = json.dumps(stable, sort_keys=True, separators=(",", ":")).encode("utf-8")
    return hashlib.sha256(blob).hexdigest()


def build_case_report(
    case_header: dict,
    files: List[dict],
    *,
    operator: str = "System",
    elapsed_s: float = 0.0,
    tool_version: str = "wiperx-recovery/0.3",
) -> dict:
    """
    Build the recovery report dict (pre-signature).

    Args:
        case_header  : acquire.Case.manifest_header() output.
        files        : per-file record dicts from the recovery pipeline.
        operator     : operator name.
        elapsed_s    : wall-clock duration of the recovery run.
        tool_version : tool version string.

    Returns:
        dict
    """
    ordered = sorted(files, key=lambda f: (f.get("offset", 0), f.get("seq", 0)))

    by_method = Counter(f.get("source_method", "carve") for f in ordered)
    by_category = Counter(f.get("category", "other") for f in ordered)
    by_validation = Counter(f.get("validation_state", "unchecked") for f in ordered)
    by_band = Counter(f.get("confidence_band", "low") for f in ordered)

    return {
        "wiperx_recovery_report": {
            "schema_version": SCHEMA_VERSION,
            "generated_at": datetime.utcnow().isoformat() + "Z",
            "tool_version": tool_version,
            "operator": operator,
            "elapsed_s": round(elapsed_s, 3),
        },
        "case": case_header,
        "summary": {
            "total": len(ordered),
            "by_method": dict(by_method),
            "by_category": dict(by_category),
            "by_validation": dict(by_validation),
            "by_confidence_band": dict(by_band),
        },
        "manifest_sha256": _manifest_hash(ordered),
        "files": ordered,
        "chain_of_custody": {
            "source_sha256": case_header.get("source", {}).get("sha256"),
            "read_only": True,
            "reads_logged": case_header.get("reads_logged", 0),
        },
        "compliance": {"standard": "forensic best practice", "note": COMPLIANCE_NOTE},
    }


def write_signed_case_report(case_dir: str, report: dict) -> Tuple[Path, bool]:
    """
    Write the report as signed JSON (falls back to unsigned if crypto absent).

    Returns:
        (path, signed)
    """
    out = Path(case_dir) / "case_report.json"
    try:
        from core.report_signer import write_signed_json

        write_signed_json(report, out)
        logger.info("[case_report] signed report -> %s", out)
        return out, True
    except Exception as exc:  # noqa: BLE001
        logger.warning("[case_report] unsigned (%s)", exc)
        out.write_text(json.dumps({"payload": report, "signature": None}, indent=2))
        return out, False


def load_and_verify(path: str) -> dict:
    """Verify a signed case report; returns core.report_signer.verify_file output."""
    from core.report_signer import verify_file

    return verify_file(path)
