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

Post-erase verification (Linux + root, filefrag available) samples each
file's former physical extents via core.eraser_file.verify and records the
result in the certificate; on every other platform it is reported as skipped.
"""

from __future__ import annotations

import json
import logging
import os
import platform
import socket
from dataclasses import asdict, is_dataclass
from datetime import datetime
from pathlib import Path
from typing import Callable, Optional

from core import report_signer
from core.audit_logger import log_event
from core.eraser_file import trace_scrubber, verify
from core.eraser_file.batch import shred_paths

logger = logging.getLogger(__name__)

LogCB = Optional[Callable[[str], None]]

REPORTS_DIR = Path(__file__).parent.parent.parent / "reports"

COMPLIANCE_NOTE = (
    "Overwrite-based secure deletion of logical media, mapped to NIST SP 800-88 "
    "Rev.1 'Clear'. Does not guarantee destruction of copies held in filesystem "
    "journals, snapshots, backups, or SSD over-provisioned areas."
)


def shredder_available() -> bool:
    """True when the file-shredder batch module is importable (normal install)."""
    return shred_paths is not None


def _to_dict(obj):
    if is_dataclass(obj):
        return asdict(obj)
    if isinstance(obj, dict):
        return obj
    return {"value": repr(obj)}


def _linux_root() -> bool:
    """True on Linux running as uid 0 (needed for raw-device extent sampling)."""
    return (
        platform.system() == "Linux"
        and hasattr(os, "geteuid")
        and os.geteuid() == 0
    )


def _capture_extent_map(path_list) -> dict:
    """
    Best-effort {path: (device, extents)} for regular files, captured *before*
    shredding. Only attempted on Linux as root with filefrag available;
    returns {} otherwise so callers degrade gracefully.
    """
    if not _linux_root():
        return {}
    out = {}
    for p in path_list:
        try:
            if not os.path.isfile(p):
                continue
            device = trace_scrubber.containing_device(p)
            extents = trace_scrubber.file_block_map(p)
        except OSError:
            continue
        if device and extents:
            out[p] = (device, extents)
    return out


def _verify_after_erase(pre_extent_map: dict, log_callback: LogCB = None) -> dict:
    """Sample each captured file's former extents and confirm they read zero."""
    method = "core.eraser_file.verify.verify_extents_zeroed"
    if not _linux_root():
        return {
            "status": "skipped",
            "method": method,
            "reason": "post-erase extent sampling requires Linux + root + filefrag",
        }
    if not pre_extent_map:
        return {
            "status": "skipped",
            "method": method,
            "reason": "no regular-file extent maps could be captured before erase",
        }

    checks = []
    all_ok = True
    for path, (device, extents) in pre_extent_map.items():
        try:
            res = verify.verify_extents_zeroed(
                device, extents, samples=64, log_callback=log_callback
            )
        except OSError as exc:  # noqa: BLE001 - record, never abort the run
            res = {"verified": False, "details": f"{exc.__class__.__name__}: {exc}"}
        res["path"] = path
        checks.append(res)
        all_ok = all_ok and bool(res.get("verified"))

    return {
        "status": "performed",
        "method": method,
        "all_extents_zeroed": all_ok,
        "checks": checks,
    }


def build_erase_report(
    *,
    operator: str,
    batch_summary,
    free_space: Optional[dict],
    trim: Optional[dict],
    options: dict,
    verification: Optional[dict] = None,
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
        "verification": verification or {"status": "skipped", "reason": "not requested"},
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
        dict: {summary, files, certificate_path, certificate_signed, report,
               free_space_wipe, fstrim}
    """
    path_list = [str(p) for p in paths]
    pre_extent_map = _capture_extent_map(path_list)
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

    verification = _verify_after_erase(pre_extent_map, log_callback)

    report = build_erase_report(
        operator=operator,
        batch_summary=summary,
        free_space=free_space,
        trim=trim,
        options=options,
        verification=verification,
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
