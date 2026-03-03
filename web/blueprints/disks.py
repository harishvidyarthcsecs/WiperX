# wiperx/web/blueprints/disks.py
"""Disks Blueprint — Disk scanning and listing."""

from flask import Blueprint, render_template, request, jsonify, flash, redirect, url_for, session
from flask_login import login_required, current_user
from web.models import get_machine_store
from core.execution_manager import ExecutionManager, ExecutionMode, RemoteConnectionConfig
from core.audit_logger import log_event

disks_bp = Blueprint("disks", __name__)


@disks_bp.route("/scan/local")
@login_required
def scan_local():
    if not current_user.can("scan"):
        flash("Access denied.", "danger")
        return redirect(url_for("dashboard.index"))

    manager = ExecutionManager()
    error = None
    disks = []

    try:
        disks = manager.scan_disks(mode=ExecutionMode.LOCAL)
        log_event("disk_scan_local", {"user": current_user.username, "disk_count": len(disks)})
    except Exception as e:
        error = str(e)

    return render_template("disks/scan_results.html", disks=disks, target="Local Machine", error=error)


@disks_bp.route("/scan/remote/<machine_id>")
@login_required
def scan_remote(machine_id):
    if not current_user.can("scan"):
        flash("Access denied.", "danger")
        return redirect(url_for("dashboard.index"))

    store = get_machine_store()
    machine = store.get(machine_id)
    if not machine:
        flash("Machine not found.", "danger")
        return redirect(url_for("machines.index"))

    manager = ExecutionManager()
    disks = []
    error = None

    try:
        if machine.connection_type == "ssh":
            exec_mode = ExecutionMode.REMOTE_SSH
            remote_config = RemoteConnectionConfig(
                hostname=machine.hostname,
                mode=exec_mode,
                ssh_username=machine.ssh_username,
                ssh_key_path=machine.ssh_key_path,
                ssh_port=machine.ssh_port,
            )
        else:
            exec_mode = ExecutionMode.REMOTE_WINRM
            remote_config = RemoteConnectionConfig(
                hostname=machine.hostname,
                mode=exec_mode,
                winrm_username=machine.winrm_username,
                winrm_port=machine.winrm_port,
            )

        disks = manager.scan_disks(mode=exec_mode, remote_config=remote_config)
        log_event("disk_scan_remote", {
            "user": current_user.username,
            "machine": machine.hostname,
            "disk_count": len(disks),
        })

    except Exception as e:
        error = str(e)

    return render_template(
        "disks/scan_results.html",
        disks=disks,
        target=machine.hostname,
        machine_id=machine_id,
        error=error,
    )
