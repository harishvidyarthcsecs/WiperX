# wiperx/web/blueprints/recovery.py
"""
Recovery Blueprint (Module 3)
-----------------------------
Web UI for Advanced File Carving & Recovery: pick a source (device or image),
run core.recovery.service.recover in a background thread, stream its log via
SSE, then browse the signed forensic case report and download recovered files.

Safety:
  - Requires the "recover" permission (ADMIN / OPERATOR).
  - A source under /dev/ additionally requires the ADMIN role.
  - If WIPERX_RECOVER_ALLOWED_ROOT is configured, an image source must resolve
    inside it.
  - Case output goes to <repo>/cases/<name>/ ; the source is opened read-only
    by the recovery engine.
"""

from __future__ import annotations

import json
import os
import queue
import secrets
import threading
from datetime import datetime
from pathlib import Path

from flask import (
    Blueprint, render_template, request, redirect, url_for, flash, session,
    Response, stream_with_context, jsonify, send_file, abort, current_app,
)
from flask_login import login_required, current_user

from core import report_signer
from core.audit_logger import log_event
from core.recovery import service
from web.models import UserRole

recovery_bp = Blueprint("recovery", __name__)

CASES_DIR = Path(__file__).parent.parent.parent / "cases"

# In-memory queue for streaming recovery logs, keyed by user id (mirrors wipe.py)
_recovery_queues: dict = {}

_MODES = ("full", "carve-only", "fs-only")


def _allowed_root():
    root = os.environ.get("WIPERX_RECOVER_ALLOWED_ROOT") or current_app.config.get(
        "RECOVER_ALLOWED_ROOT"
    )
    return Path(root).resolve() if root else None


def _source_ok(source: str):
    """Return (ok, error) for a submitted recovery source path."""
    if not source:
        return False, "Provide a device or image path."
    if source.startswith("/dev/") and current_user.role != UserRole.ADMIN:
        return False, "Only an administrator may recover directly from a device."
    if not os.path.exists(source):
        return False, f"Source does not exist: {source}"
    root = _allowed_root()
    if root is not None and not source.startswith("/dev/"):
        try:
            rp = Path(source).resolve()
        except OSError:
            return False, f"Cannot resolve path: {source}"
        if root not in rp.parents and rp != root:
            return False, f"Path outside allowed root ({root}): {source}"
    return True, None


def _cases_root() -> Path:
    return CASES_DIR.resolve()


@recovery_bp.route("/", methods=["GET", "POST"])
@login_required
def index():
    if not current_user.can("recover"):
        flash("Access denied: recover permission required.", "danger")
        return redirect(url_for("dashboard.index"))

    if request.method == "POST":
        return submit()

    return render_template("recovery/index.html", allowed_root=_allowed_root())


def submit():
    source = request.form.get("source", "").strip()
    mode = request.form.get("mode", "full")
    if mode not in _MODES:
        mode = "full"
    allow_mounted = request.form.get("allow_mounted") == "on"
    operator = request.form.get("operator", "").strip() or current_user.username

    ok, err = _source_ok(source)
    if not ok:
        flash(err, "danger")
        return redirect(url_for("recovery.index"))

    session["pending_recovery"] = {
        "source": source,
        "mode": mode,
        "allow_mounted": allow_mounted,
        "operator": operator,
    }
    return redirect(url_for("recovery.execute"))


@recovery_bp.route("/execute")
@login_required
def execute():
    if not current_user.can("recover"):
        flash("Access denied.", "danger")
        return redirect(url_for("dashboard.index"))
    pending = session.get("pending_recovery")
    if not pending:
        flash("No pending recovery operation found.", "warning")
        return redirect(url_for("recovery.index"))
    return render_template("recovery/run.html", pending=pending)


@recovery_bp.route("/run", methods=["POST"])
@login_required
def run_recovery():
    if not current_user.can("recover"):
        return jsonify({"error": "Access denied"}), 403

    pending = session.get("pending_recovery")
    if not pending:
        return jsonify({"error": "No pending recovery"}), 400

    source = pending["source"]
    operator = pending["operator"]
    allow_mounted = bool(pending.get("allow_mounted"))
    mode = pending.get("mode", "full")
    carve_only = mode == "carve-only"
    fs_only = mode == "fs-only"

    name = "web-" + datetime.utcnow().strftime("%Y%m%dT%H%M%SZ") + "-" + secrets.token_hex(3)
    case_dir = CASES_DIR / name

    session_id = current_user.id
    log_queue = queue.Queue()
    _recovery_queues[session_id] = log_queue

    def run_in_thread():
        try:
            def log_cb(msg):
                log_queue.put({"type": "log", "message": str(msg)})

            res = service.recover(
                source, str(case_dir), operator=operator,
                carve_only=carve_only, fs_only=fs_only,
                allow_mounted=allow_mounted, log_callback=log_cb,
            )
            log_queue.put({
                "type": "done",
                "success": True,
                "case_name": name,
                "total": res["summary"].get("total", 0),
                "signed": res["signed"],
                "manifest_sha256": res["manifest_sha256"],
            })
        except Exception as exc:  # noqa: BLE001 - surface to the operator
            log_queue.put({
                "type": "done",
                "success": False,
                "error": str(exc),
                "case_name": name,
            })

    threading.Thread(target=run_in_thread, daemon=True).start()

    log_event("web_recovery_submitted", {
        "user": current_user.username, "source": source, "mode": mode,
        "case_name": name,
    })
    return jsonify({"status": "started"})


@recovery_bp.route("/stream/<session_id>")
@login_required
def stream_logs(session_id):
    """Server-Sent Events endpoint for real-time recovery log streaming."""

    def generate():
        q = _recovery_queues.get(current_user.id)
        if not q:
            yield f"data: {json.dumps({'type': 'error', 'message': 'No active recovery'})}\n\n"
            return
        while True:
            try:
                item = q.get(timeout=30)
                yield f"data: {json.dumps(item)}\n\n"
                if item.get("type") == "done":
                    _recovery_queues.pop(current_user.id, None)
                    break
            except queue.Empty:
                yield f"data: {json.dumps({'type': 'heartbeat'})}\n\n"

    return Response(
        stream_with_context(generate()),
        content_type="text/event-stream",
        headers={"Cache-Control": "no-cache", "X-Accel-Buffering": "no"},
    )


def _load_case(name: str):
    """Return (safe_name, report_path, envelope) or abort(404)."""
    safe = os.path.basename(name)
    rep = CASES_DIR / safe / "case_report.json"
    try:
        resolved = rep.resolve()
    except OSError:
        abort(404)
    if not rep.exists() or not str(resolved).startswith(str(_cases_root())):
        abort(404)
    try:
        envelope = json.loads(rep.read_text(encoding="utf-8"))
    except (OSError, ValueError):
        abort(404)
    return safe, rep, envelope


@recovery_bp.route("/cases/")
@login_required
def cases():
    if not current_user.can("recover"):
        flash("Access denied.", "danger")
        return redirect(url_for("dashboard.index"))

    items = []
    if CASES_DIR.exists():
        for rep in sorted(CASES_DIR.glob("*/case_report.json"), reverse=True):
            try:
                envelope = json.loads(rep.read_text(encoding="utf-8"))
            except (OSError, ValueError):
                continue
            payload = envelope.get("payload") or {}
            summary = payload.get("summary") or {}
            meta = payload.get("wiperx_recovery_report") or {}
            verify = report_signer.verify_file(str(rep))
            items.append({
                "name": rep.parent.name,
                "total": summary.get("total", 0),
                "generated_at": meta.get("generated_at", ""),
                "operator": meta.get("operator", ""),
                "valid": verify.get("valid", False),
                "trusted": verify.get("trusted", False),
            })
    return render_template("recovery/cases.html", cases=items)


@recovery_bp.route("/case/<name>")
@login_required
def case_detail(name):
    if not current_user.can("recover"):
        flash("Access denied.", "danger")
        return redirect(url_for("dashboard.index"))

    safe, rep, envelope = _load_case(name)
    payload = envelope.get("payload") or {}
    verify = report_signer.verify_file(str(rep))
    return render_template(
        "recovery/case.html",
        name=safe,
        meta=payload.get("wiperx_recovery_report", {}),
        case=payload.get("case", {}),
        summary=payload.get("summary", {}),
        files=payload.get("files", []),
        coc=payload.get("chain_of_custody", {}),
        verify=verify,
    )


@recovery_bp.route("/case/<name>/file/<fname>")
@login_required
def case_file(name, fname):
    if not current_user.can("download_reports"):
        abort(403)
    safe_name = os.path.basename(name)
    safe_file = os.path.basename(fname)
    recovered_dir = CASES_DIR / safe_name / "recovered"
    fp = recovered_dir / safe_file
    try:
        resolved = fp.resolve()
    except OSError:
        abort(404)
    if not fp.exists() or not str(resolved).startswith(str(recovered_dir.resolve())):
        abort(404)
    as_attach = request.args.get("dl") == "1"
    return send_file(fp, as_attachment=as_attach)
