# wiperx/core/eraser_file/service.py
"""
Erase Service
-------------
Single orchestration entry point for the Secure File & Folder Eraser,
shared by the CLI and the Flask blueprint so neither contains erase logic.

An erase run:
  1. Shreds every requested file (core.eraser_file.batch.shred_paths).
  2. Optionally clears free space on a mount + issues fstrim.
  3. Writes an audit-log event for the run.
  4. Builds a report dict and writes it as a signed JSON certificate.

file_shredder / batch are the Codex-owned Phase 1 deliverables; until they
land this module raises a clear RuntimeError from erase_paths().
"""

from __future__ import annotations

import json
import logging
import platform
import socket
from dataclasses import asdict, is_dataclass
from datetime import datetime
from pathlib import Path
from typing import Callable, Optional

from core import report_signer
from core.audit_logger import log_event
from core.eraser_file import trace_scrubber

logger = logging.getLogger(__name__)

LogCB = Optional[Callable[[str], None]]

REPORTS_DIR = Path(__file__).parent.parent.parent / "reports"

try:
    from core.eraser_file.batch import shred_paths

    _SHREDDER_AVAILABLE = True
except ImportError:  # Codex Phase 1 deliverable not present yet
    shred_paths = None  # type: ignore
    _SHREDDER_AVAILABLE = False

COMPLIANCE_NOTE = (
    "Overwrite-based secure deletion of logical media, mapped to NIST SP 800-88 "
    "Rev.1 'Clear'. Does not guarantee destruction of copies held in filesystem "
    "journals, snapshots, backups, or SSD over-provisioned areas."
)


def shredder_available() -> bool:
    """True once core.eraser_file.batch.shred_paths is importable."""
    return _SHREDDER_AVAILABLE


def _to_dict(obj):
    if is_dataclass(obj):
        return asdict(obj)
    if isinstance(obj, dict):
        return obj
    return {"value": repr(obj)}


def build_erase_report(
    *,
    operator: str,
    batch_summary,
    free_space: Optional[dict],
    trim: Optional[dict],
    options: dict,
) -> dict:
    """Assemble the machine-readable erase report (pre-signature)."""
    summary = _to_dict(batch_summary)
    results = [_to_dict(r) for r in summary.pop("results", [])]

    return {
        "wiperx_erase_report": {
            "schema_version": "1.0",
            "generated_at": datetime.utcnow().isoformat() + "Z",
            "operator": operator,
            "host": socket.gethostname(),
            "os": platform.platform(),
        },
        "options": options,
        "summary": summary,
        "files": results,
        "free_space_wipe": free_space,
        "fstrim": trim,
        "compliance": {
            "standard": "NIST SP 800-88 Rev.1 (Guidelines for Media Sanitization)",
            "category": "Clear",
            "note": COMPLIANCE_NOTE,
        },
    }


def erase_paths(
    paths,
    *,
    recursive: bool = True,
    passes: int = 1,
    zero_final: bool = True,
    rename_rounds: int = 3,
    workers: int = 4,
    operator: str = "System",
    wipe_free_mount: Optional[str] = None,
    fstrim_after: bool = False,
    reports_dir: Optional[Path] = None,
    log_callback: LogCB = None,
) -> dict:
    """
    Run a full erase operation and emit a signed certificate.

    Args:
        paths           : Iterable of file/folder paths to erase.
        recursive       : Recurse into directories.
        passes          : Random overwrite passes per file.
        zero_final      : Trailing zero pass per file.
        rename_rounds   : Random rename rounds before unlink.
        workers         : Thread pool size for the batch.
        operator        : Name recorded in the certificate.
        wipe_free_mount : If set, fill free space on this mount after shredding.
        fstrim_after    : If set with wipe_free_mount, run fstrim afterwards.
        reports_dir     : Override output directory for the certificate.
        log_callback    : Optional real-time log sink.

    Returns:
        dict: {summary, files, certificate_path, report, free_space_wipe, fstrim}

    Raises:
        RuntimeError : file_shredder / batch not yet available.
    """
    if not _SHREDDER_AVAILABLE:
        raise RuntimeError(
            "core.eraser_file.batch.shred_paths is not available yet "
            "(Codex Phase 1 deliverable: file_shredder.py + batch.py)."
        )

    path_list = [str(p) for p in paths]
    options = {
        "paths": path_list,
        "recursive": recursive,
        "passes": passes,
        "zero_final": zero_final,
        "rename_rounds": rename_rounds,
        "workers": workers,
    }
    log_event("file_erase.start", {"operator": operator, "options": options})

    summary = shred_paths(
        path_list,
        recursive=recursive,
        workers=workers,
        on_progress=log_callback if log_callback else None,
        passes=passes,
        zero_final=zero_final,
        rename_rounds=rename_rounds,
    )

    free_space = None
    trim = None
    if wipe_free_mount:
        free_space = trace_scrubber.wipe_free_space(
            wipe_free_mount, passes=passes, zero_final=zero_final, log_callback=log_callback
        )
        if fstrim_after:
            trim = trace_scrubber.fstrim(wipe_free_mount, log_callback=log_callback)

    report = build_erase_report(
        operator=operator,
        batch_summary=summary,
        free_space=free_space,
        trim=trim,
        options=options,
    )

    out_dir = Path(reports_dir) if reports_dir else REPORTS_DIR
    out_dir.mkdir(parents=True, exist_ok=True)
    stamp = datetime.utcnow().strftime("%Y%m%dT%H%M%SZ")
    cert_path = out_dir / f"erase_cert_{stamp}.json"
    try:
        report_signer.write_signed_json(report, cert_path)
        signed = True
    except RuntimeError as exc:  # cryptography missing
        logger.warning("[EraseService] certificate not signed: %s", exc)
        cert_path.write_text(json.dumps({"payload": report, "signature": None}, indent=2))
        signed = False

    summary_dict = _to_dict(summary)
    files = [_to_dict(r) for r in summary_dict.get("results", [])]
    log_event(
        "file_erase.done",
        {
            "operator": operator,
            "succeeded": summary_dict.get("succeeded"),
            "failed": summary_dict.get("failed"),
            "bytes_erased": summary_dict.get("bytes_erased"),
            "certificate": str(cert_path),
            "signed": signed,
        },
    )

    return {
        "summary": {k: v for k, v in summary_dict.items() if k != "results"},
        "files": files,
        "certificate_path": str(cert_path),
        "certificate_signed": signed,
        "report": report,
        "free_space_wipe": free_space,
        "fstrim": trim,
    }


def wipe_free_space_only(
    mount_point: str,
    *,
    passes: int = 1,
    zero_final: bool = True,
    fstrim_after: bool = False,
    operator: str = "System",
    reports_dir: Optional[Path] = None,
    log_callback: LogCB = None,
) -> dict:
    """Clear free space on a mount (no file list) and emit a signed certificate."""
    log_event("free_space_wipe.start", {"operator": operator, "mount": mount_point})
    free_space = trace_scrubber.wipe_free_space(
        mount_point, passes=passes, zero_final=zero_final, log_callback=log_callback
    )
    trim = (
        trace_scrubber.fstrim(mount_point, log_callback=log_callback)
        if fstrim_after
        else None
    )

    report = {
        "wiperx_erase_report": {
            "schema_version": "1.0",
            "generated_at": datetime.utcnow().isoformat() + "Z",
            "operator": operator,
            "host": socket.gethostname(),
            "os": platform.platform(),
            "operation": "free_space_wipe",
        },
        "free_space_wipe": free_space,
        "fstrim": trim,
        "compliance": {
            "standard": "NIST SP 800-88 Rev.1",
            "category": "Clear",
            "note": COMPLIANCE_NOTE,
        },
    }

    out_dir = Path(reports_dir) if reports_dir else REPORTS_DIR
    out_dir.mkdir(parents=True, exist_ok=True)
    stamp = datetime.utcnow().strftime("%Y%m%dT%H%M%SZ")
    cert_path = out_dir / f"freespace_cert_{stamp}.json"
    try:
        report_signer.write_signed_json(report, cert_path)
        signed = True
    except RuntimeError:
        cert_path.write_text(json.dumps({"payload": report, "signature": None}, indent=2))
        signed = False

    log_event(
        "free_space_wipe.done",
        {"operator": operator, "ok": free_space.get("ok"),
         "bytes_written": free_space.get("bytes_written"),
         "certificate": str(cert_path), "signed": signed},
    )
    return {
        "free_space_wipe": free_space,
        "fstrim": trim,
        "certificate_path": str(cert_path),
        "certificate_signed": signed,
        "report": report,
    }
