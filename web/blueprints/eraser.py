# wiperx/web/blueprints/eraser.py
"""
Eraser Blueprint (Module 2)
---------------------------
Web UI for the Secure File & Folder Eraser: submit a list of paths, run the
erase through core.eraser_file.service, show the summary and link to the
signed certificate.

Safety:
  - Requires the "wipe" permission (ADMIN / OPERATOR).
  - If WIPERX_ERASE_ALLOWED_ROOT is configured, every submitted path must
    resolve inside it; otherwise the request is rejected.
"""

import os
from pathlib import Path

from flask import (
    Blueprint, render_template, request, redirect, url_for, flash, current_app
)
from flask_login import login_required, current_user

from core.audit_logger import log_event
from core.eraser_file import service

eraser_bp = Blueprint("eraser", __name__)


def _allowed_root():
    root = os.environ.get("WIPERX_ERASE_ALLOWED_ROOT") or current_app.config.get(
        "ERASE_ALLOWED_ROOT"
    )
    return Path(root).resolve() if root else None


def _paths_ok(paths):
    root = _allowed_root()
    if root is None:
        return True, None
    for p in paths:
        try:
            rp = Path(p).resolve()
        except OSError:
            return False, f"Cannot resolve path: {p}"
        if root not in rp.parents and rp != root:
            return False, f"Path outside allowed root ({root}): {p}"
    return True, None


@eraser_bp.route("/", methods=["GET"])
@login_required
def index():
    if not current_user.can("wipe"):
        flash("Access denied: erase permission required.", "danger")
        return redirect(url_for("dashboard.index"))
    return render_template("eraser/index.html", allowed_root=_allowed_root())


@eraser_bp.route("/run", methods=["POST"])
@login_required
def run():
    if not current_user.can("wipe"):
        flash("Access denied: erase permission required.", "danger")
        return redirect(url_for("dashboard.index"))

    raw = request.form.get("paths", "")
    paths = [line.strip() for line in raw.splitlines() if line.strip()]
    recursive = request.form.get("recursive") == "on"
    passes = max(1, int(request.form.get("passes", 1)))
    zero_final = request.form.get("zero_final", "on") == "on"
    wipe_free_mount = request.form.get("wipe_free_mount", "").strip() or None
    fstrim_after = request.form.get("fstrim_after") == "on"
    operator = request.form.get("operator", "").strip() or current_user.username

    if not paths and not wipe_free_mount:
        flash("Provide at least one path, or a free-space mount point.", "warning")
        return redirect(url_for("eraser.index"))

    ok, err = _paths_ok(paths)
    if not ok:
        flash(err, "danger")
        return redirect(url_for("eraser.index"))

    if not service.shredder_available() and paths:
        flash("File shredder module not available on this server.", "danger")
        return redirect(url_for("eraser.index"))

    log_event("web_erase_submitted", {
        "user": current_user.username, "paths": paths,
        "recursive": recursive, "wipe_free_mount": wipe_free_mount,
    })

    log_lines = []
    try:
        if paths:
            result = service.erase_paths(
                paths, recursive=recursive, passes=passes, zero_final=zero_final,
                operator=operator, wipe_free_mount=wipe_free_mount,
                fstrim_after=fstrim_after, log_callback=log_lines.append,
            )
        else:
            result = service.wipe_free_space_only(
                wipe_free_mount, passes=passes, zero_final=zero_final,
                fstrim_after=fstrim_after, operator=operator,
                log_callback=log_lines.append,
            )
    except Exception as exc:  # noqa: BLE001 - report to the operator
        flash(f"Erase failed: {exc}", "danger")
        return redirect(url_for("eraser.index"))

    cert_name = Path(result["certificate_path"]).name
    return render_template(
        "eraser/result.html",
        result=result,
        cert_name=cert_name,
        log_lines=[str(x) for x in log_lines],
    )
