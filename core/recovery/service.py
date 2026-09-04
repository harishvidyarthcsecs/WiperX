# wiperx/core/recovery/service.py
"""
Recovery Service
----------------
Single orchestration entrypoint for Module 3, shared by the CLI and (later)
the Flask blueprint.

Pipeline:
  1. open the source read-only, hash it, create the case directory
  2. filesystem-aware undelete pass (fs_recover)      - unless carve_only
  3. signature carving pass (carver_header)           - unless fs_only
  4. per file: classify -> validate -> confidence score
  5. build + sign the forensic case report
  6. audit-log the run
"""

from __future__ import annotations

import logging
import time
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path
from typing import Callable, List, Optional

from core.audit_logger import log_event
from core.recovery import carver_header, case_report, classify, confidence, fs_recover, validate
from core.recovery.acquire import Case, open_source
from core.recovery.signatures import by_name

logger = logging.getLogger(__name__)

LogCB = Optional[Callable[[str], None]]


def _enrich(record: dict) -> dict:
    """Add classification, validation and confidence to a raw record in place."""
    path = record["recovered_path"]

    cls = classify.classify(
        path,
        fallback_sig=record.get("signature", ""),
        fallback_category=record.get("category", "other"),
    )
    record["category"] = cls.category
    record["mime"] = cls.mime
    record["classified_by"] = cls.source

    val = validate.validate(path, record.get("signature", ""), cls.category)
    record["validation_state"] = val.state
    record["validation_detail"] = val.detail
    record["validation_by"] = val.validator

    score = confidence.score_from_record(record, validation_state=val.state)
    record["confidence_score"] = score.score
    record["confidence_band"] = score.band
    record["confidence_factors"] = score.factors
    return record


def recover(
    source_path: str,
    out_dir: str,
    *,
    operator: str = "System",
    carve_only: bool = False,
    fs_only: bool = False,
    allow_mounted: bool = False,
    log_callback: LogCB = None,
) -> dict:
    """
    Run a full recovery.

    Args:
        source_path   : /dev/sdX or a .dd / .img image.
        out_dir       : case output directory (created if absent).
        operator      : name recorded in the report.
        carve_only    : skip the filesystem-aware pass.
        fs_only       : skip the carving pass.
        allow_mounted : proceed on a rw-mounted device (unsafe).
        log_callback  : optional real-time log sink.

    Returns:
        dict: {case_id, case_dir, report_path, signed, manifest_sha256,
               summary, records}
    """
    def _log(msg: str) -> None:
        logger.info("[recovery] %s", msg)
        if log_callback:
            log_callback(f"[recovery] {msg}")

    started = time.perf_counter()
    src = open_source(source_path, allow_mounted=allow_mounted)
    hash_pool: Optional[ThreadPoolExecutor] = None
    try:
        case = Case(out_dir, src, operator=operator)
        _log(f"case {case.case_id} -> {case.dir}")

        # hashlib/os.read release the GIL, so hash the whole source in the
        # background while the fs-recovery/carve passes run on the main
        # thread instead of serializing "hash everything" before "carve
        # everything". Source.sha256() caches its result, so whichever
        # caller needs it later (manifest_header() below) just blocks on
        # this future finishing rather than re-hashing.
        _log("hashing source in background while recovery runs ...")
        hash_pool = ThreadPoolExecutor(max_workers=1)
        hash_future = hash_pool.submit(src.sha256)

        log_event("recovery.start", {
            "operator": operator, "source": source_path, "case_id": case.case_id,
            "carve_only": carve_only, "fs_only": fs_only,
        })

        records: List[dict] = []
        allocated = []

        if not carve_only:
            _log("filesystem-aware undelete pass ...")
            fsr = fs_recover.recover_filesystem(source_path, str(case.dir))
            _log(f"fs pass: {fsr.note}")
            records.extend(fsr.records)
            allocated = fsr.allocated_ranges

        if not fs_only:
            _log("signature carving pass ...")

            def _carve_progress(cf) -> None:
                _log(f"carved {cf.sig_name} @ {cf.offset:#x} ({cf.size} B, {cf.method})")

            carved = carver_header.carve(
                src, str(case.dir), allocated_ranges=allocated,
                on_progress=_carve_progress,
            )
            for cf in carved:
                sig = by_name(cf.sig_name)
                records.append({
                    "source_method": "carve",
                    "seq": cf.seq,
                    "offset": cf.offset,
                    "end": cf.end,
                    "size": cf.size,
                    "sha256": cf.sha256,
                    "signature": cf.sig_name,
                    "category": cf.category,
                    "carve_method": cf.method,
                    "footer_found": cf.footer_found,
                    "recovered_name": Path(cf.path).name,
                    "recovered_path": cf.path,
                    "sig_min": sig.min_bytes if sig else 0,
                    "sig_max": sig.max_bytes if sig else (1 << 40),
                    "notes": cf.notes,
                })

        _log(f"enriching {len(records)} record(s) (classify / validate / score) ...")
        for rec in records:
            _enrich(rec)
            rec["recovered_path"] = str(Path(rec["recovered_path"]).relative_to(case.dir))

        hash_future.result()  # join the background hash; propagates any read error
        header = case.manifest_header()
        elapsed = time.perf_counter() - started
        report = case_report.build_case_report(
            header, records, operator=operator, elapsed_s=elapsed,
        )
        report_path, signed = case_report.write_signed_case_report(str(case.dir), report)

        summary = report["summary"]
        _log(f"done: {summary['total']} file(s) in {elapsed:.1f}s -> {report_path} "
             f"(signed={signed})")
        log_event("recovery.done", {
            "operator": operator, "case_id": case.case_id,
            "total": summary["total"], "by_method": summary["by_method"],
            "by_validation": summary["by_validation"],
            "manifest_sha256": report["manifest_sha256"],
            "report": str(report_path), "signed": signed,
        })

        return {
            "case_id": case.case_id,
            "case_dir": str(case.dir),
            "report_path": str(report_path),
            "signed": signed,
            "manifest_sha256": report["manifest_sha256"],
            "summary": summary,
            "records": records,
        }
    finally:
        if hash_pool is not None:
            hash_pool.shutdown(wait=False)
        src.close()
