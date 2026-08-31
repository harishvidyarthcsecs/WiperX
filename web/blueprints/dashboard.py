# wiperx/web/blueprints/dashboard.py
"""Dashboard Blueprint — unified overview + audit log view."""

import socket
import platform
from pathlib import Path

from flask import Blueprint, render_template, redirect, url_for, flash
from flask_login import login_required, current_user

from core import report_signer
from core.audit_logger import read_recent_events
from web.models import get_machine_store

dashboard_bp = Blueprint("dashboard", __name__)

_ROOT = Path(__file__).parent.parent.parent
REPORTS_DIR = _ROOT / "reports"
CASES_DIR = _ROOT / "cases"


def _report_counts() -> dict:
    counts = {"wipe": 0, "erase": 0, "freespace": 0, "other": 0}
    if REPORTS_DIR.exists():
        for f in REPORTS_DIR.glob("*.json"):
            if f.name.startswith(("wipe_cert_", "wipe_report_")):
                counts["wipe"] += 1
            elif f.name.startswith("erase_cert_"):
                counts["erase"] += 1
            elif f.name.startswith("freespace_cert_"):
                counts["freespace"] += 1
            else:
                counts["other"] += 1
    return counts


def _recent_reports(limit: int = 5) -> list:
    """Newest JSON reports + recovery cases, each with a signature verdict."""
    entries = []
    if REPORTS_DIR.exists():
        for f in sorted(REPORTS_DIR.glob("*.json"), reverse=True)[:limit]:
            v = report_signer.verify_file(str(f))
            entries.append({
                "name": f.name, "kind": "report",
                "valid": v.get("valid", False), "trusted": v.get("trusted", False),
                "url": url_for("reports.view", filename=f.name),
            })
    if CASES_DIR.exists():
        for rep in sorted(CASES_DIR.glob("*/case_report.json"), reverse=True)[:limit]:
            v = report_signer.verify_file(str(rep))
            entries.append({
                "name": rep.parent.name, "kind": "recovery case",
                "valid": v.get("valid", False), "trusted": v.get("trusted", False),
                "url": url_for("recovery.case_detail", name=rep.parent.name),
            })
    return entries[: limit * 2]


@dashboard_bp.route("/")
@login_required
def index():
    machines = list(get_machine_store().values())
    counts = _report_counts()
    case_count = len(list(CASES_DIR.glob("*/case_report.json"))) if CASES_DIR.exists() else 0

    system_info = {
        "hostname": socket.gethostname(),
        "os": platform.system(),
        "os_version": platform.version(),
        "python": platform.python_version(),
    }

    return render_template(
        "dashboard/index.html",
        machine_count=len(machines),
        report_counts=counts,
        case_count=case_count,
        system_info=system_info,
        machines=machines[:5],
        recent_events=read_recent_events(12),
        recent_reports=_recent_reports(5),
    )


@dashboard_bp.route("/audit")
@login_required
def audit():
    if not current_user.can("view_logs"):
        flash("Access denied: audit-log permission required.", "danger")
        return redirect(url_for("dashboard.index"))
    return render_template("dashboard/audit.html", events=read_recent_events(200))
