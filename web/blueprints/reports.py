# wiperx/web/blueprints/reports.py
"""Reports Blueprint — Report listing and download."""

import json
import os
from pathlib import Path
from flask import Blueprint, render_template, send_file, abort, flash, redirect, url_for
from flask_login import login_required, current_user

reports_bp = Blueprint("reports", __name__)
REPORTS_DIR = Path(__file__).parent.parent.parent / "reports"


@reports_bp.route("/")
@login_required
def index():
    reports = []
    if REPORTS_DIR.exists():
        for f in sorted(REPORTS_DIR.glob("*.json"), reverse=True):
            try:
                with open(f) as fh:
                    data = json.load(fh)
                reports.append({
                    "filename": f.name,
                    "timestamp": data.get("operation", {}).get("timestamp", "Unknown"),
                    "hostname": data.get("target", {}).get("hostname", "Unknown"),
                    "disk": data.get("target", {}).get("disk_identifier", "Unknown"),
                    "success": data.get("operation", {}).get("success", False),
                    "strategy": data.get("wipe", {}).get("strategy_used", "Unknown"),
                })
            except Exception:
                pass

    return render_template("reports/index.html", reports=reports)


@reports_bp.route("/download/<filename>")
@login_required
def download(filename):
    if not current_user.can("download_reports"):
        flash("Access denied.", "danger")
        return redirect(url_for("reports.index"))

    # Security: prevent path traversal
    safe_filename = os.path.basename(filename)
    file_path = REPORTS_DIR / safe_filename

    if not file_path.exists() or not str(file_path).startswith(str(REPORTS_DIR)):
        abort(404)

    return send_file(file_path, as_attachment=True)


@reports_bp.route("/view/<filename>")
@login_required
def view(filename):
    safe_filename = os.path.basename(filename)
    file_path = REPORTS_DIR / safe_filename

    if not file_path.exists():
        abort(404)

    with open(file_path) as f:
        data = json.load(f)

    return render_template("reports/view.html", report=data, filename=safe_filename)
