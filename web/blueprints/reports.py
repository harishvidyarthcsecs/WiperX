# wiperx/web/blueprints/reports.py
"""Reports Blueprint — unified listing / view / download for every certificate.

Handles all four report kinds (wipe / erase / freespace / recover), the signed
`{ "payload": {...}, "signature": {...} }` envelope, the legacy flat filenames
and the new `reports/<YYYY-MM-DD>/<kind>_<target>_<HHMMSS>Z.json` layout.
"""

import json
from pathlib import Path

from flask import (
    Blueprint, render_template, send_file, abort, flash, redirect, url_for,
)
from flask_login import login_required, current_user

from core import report_signer
from core.report_paths import kind_of

reports_bp = Blueprint("reports", __name__)

_ROOT = Path(__file__).parent.parent.parent
REPORTS_DIR = _ROOT / "reports"
CASES_DIR = _ROOT / "cases"


# --------------------------------------------------------------------------- #
# helpers
# --------------------------------------------------------------------------- #

def _unwrap(obj):
    """Return the report body, stripping the signed envelope if present."""
    if isinstance(obj, dict) and "payload" in obj and "signature" in obj:
        return obj["payload"] or {}
    return obj or {}


def _rel(path: Path) -> str:
    """Path relative to REPORTS_DIR, or 'cases/<...>' for recovery reports."""
    try:
        return str(path.relative_to(REPORTS_DIR))
    except ValueError:
        pass
    try:
        return str(path.relative_to(_ROOT))
    except ValueError:
        return path.name


def _fmt_ts(value) -> str:
    return str(value or "").replace("T", " ").replace("Z", " UTC").strip() or "—"


def _summarize(path: Path) -> dict:
    """One normalized row for the reports table."""
    row = {
        "relpath": _rel(path), "filename": path.name, "kind": kind_of(path.name),
        "timestamp": "", "host": "—", "target": "—", "detail": "—",
        "ok": None, "verified": None, "signed": False, "trusted": False,
    }
    try:
        with open(path) as fh:
            payload = _unwrap(json.load(fh))
    except Exception:  # noqa: BLE001 - unreadable file still shows a row
        row["detail"] = "unreadable"
        row["ok"] = False
        return row

    sig = report_signer.verify_file(str(path))
    row["signed"] = bool(sig.get("valid"))
    row["trusted"] = bool(sig.get("trusted"))

    k = row["kind"]
    if k == "wipe":
        op = payload.get("operation", {})
        tgt = payload.get("target", {})
        wipe = payload.get("wipe", {})
        ver = payload.get("verification", {})
        row["timestamp"] = _fmt_ts(op.get("timestamp"))
        row["host"] = tgt.get("hostname") or "—"
        row["target"] = tgt.get("disk_identifier") or "—"
        row["detail"] = wipe.get("strategy_used") or wipe.get("method") or "—"
        row["ok"] = bool(op.get("success"))
        row["verified"] = ver.get("verified")
    elif k in ("erase", "freespace"):
        meta = payload.get("wiperx_erase_report", {})
        row["timestamp"] = _fmt_ts(meta.get("generated_at"))
        row["host"] = meta.get("host") or "—"
        if k == "erase":
            s = payload.get("summary", {})
            total = s.get("total", 0)
            row["target"] = f"{total} path(s)"
            row["detail"] = f"{s.get('succeeded', 0)}/{total} erased"
            row["ok"] = s.get("failed", 1) == 0 and total > 0
        else:
            fs = payload.get("free_space_wipe", {})
            row["target"] = fs.get("mount") or fs.get("mount_point") or "free space"
            mb = (fs.get("bytes_written", 0) or 0) / (1024 * 1024)
            row["detail"] = f"{mb:,.0f} MiB written"
            row["ok"] = bool(fs.get("ok"))
    elif k == "recover":
        hdr = payload.get("manifest", payload.get("case", {})) or {}
        summ = payload.get("summary", {})
        meta = payload.get("wiperx_case_report", {})
        row["timestamp"] = _fmt_ts(hdr.get("started_at") or meta.get("generated_at"))
        row["host"] = hdr.get("host") or "—"
        src = (hdr.get("source", {}) or {}).get("path", "")
        row["target"] = Path(src).name or src or "—"
        row["detail"] = f"{summ.get('total', 0)} file(s) recovered"
        row["ok"] = True
    return row


def _all_report_files():
    if REPORTS_DIR.exists():
        yield from REPORTS_DIR.glob("**/*.json")
    if CASES_DIR.exists():
        yield from CASES_DIR.glob("**/case_report.json")


def _safe_under(base: Path, relpath: str) -> Path:
    target = (base / relpath).resolve()
    if not str(target).startswith(str(base.resolve())):
        abort(404)
    if not target.exists():
        abort(404)
    return target


def _resolve(relpath: str) -> Path:
    """Accept a path under reports/ or a 'cases/<...>' recovery report."""
    if relpath.replace("\\", "/").startswith("cases/"):
        return _safe_under(_ROOT, relpath)
    return _safe_under(REPORTS_DIR, relpath)


# --------------------------------------------------------------------------- #
# routes
# --------------------------------------------------------------------------- #

@reports_bp.route("/")
@login_required
def index():
    rows = [_summarize(f) for f in _all_report_files()]
    rows.sort(key=lambda r: r["timestamp"], reverse=True)
    return render_template("reports/index.html", reports=rows)


@reports_bp.route("/download/<path:filename>")
@login_required
def download(filename):
    if not current_user.can("download_reports"):
        flash("Access denied.", "danger")
        return redirect(url_for("reports.index"))
    return send_file(_resolve(filename), as_attachment=True)


@reports_bp.route("/view/<path:filename>")
@login_required
def view(filename):
    path = _resolve(filename)
    with open(path) as f:
        raw = json.load(f)
    sig = report_signer.verify_file(str(path))
    return render_template(
        "reports/view.html",
        report=_unwrap(raw),
        raw=raw,
        filename=filename,
        kind=kind_of(path.name),
        signature=sig,
    )
