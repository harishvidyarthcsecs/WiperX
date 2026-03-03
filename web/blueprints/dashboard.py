# wiperx/web/blueprints/dashboard.py
"""Dashboard Blueprint — Main overview page."""

import os
import socket
import platform
from flask import Blueprint, render_template
from flask_login import login_required, current_user
from web.models import get_machine_store
from pathlib import Path

dashboard_bp = Blueprint("dashboard", __name__)

REPORTS_DIR = Path(__file__).parent.parent.parent / "reports"


@dashboard_bp.route("/")
@login_required
def index():
    machines = list(get_machine_store().values())
    report_count = len(list(REPORTS_DIR.glob("*.json"))) if REPORTS_DIR.exists() else 0

    system_info = {
        "hostname": socket.gethostname(),
        "os": platform.system(),
        "os_version": platform.version(),
        "python": platform.python_version(),
    }

    return render_template(
        "dashboard/index.html",
        machine_count=len(machines),
        report_count=report_count,
        system_info=system_info,
        machines=machines[:5],  # Show last 5
    )
