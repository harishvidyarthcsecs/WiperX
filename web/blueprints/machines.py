# wiperx/web/blueprints/machines.py
"""Machines Blueprint — Remote machine management."""

import uuid
from flask import Blueprint, render_template, request, redirect, url_for, flash, jsonify
from flask_login import login_required, current_user
from web.models import get_machine_store, RemoteMachine
from core.audit_logger import log_event

machines_bp = Blueprint("machines", __name__)


def _require_admin():
    if not current_user.can("manage_machines"):
        flash("Access denied: Admin role required.", "danger")
        return redirect(url_for("dashboard.index"))
    return None


@machines_bp.route("/")
@login_required
def index():
    machines = list(get_machine_store().values())
    return render_template("machines/index.html", machines=machines)


@machines_bp.route("/add", methods=["GET", "POST"])
@login_required
def add():
    err = _require_admin()
    if err:
        return err

    if request.method == "POST":
        machine_id = str(uuid.uuid4())[:8]
        conn_type = request.form.get("connection_type", "ssh")

        machine = RemoteMachine(
            machine_id=machine_id,
            hostname=request.form.get("hostname", "").strip(),
            os_type=request.form.get("os_type", "unknown"),
            connection_type=conn_type,
            ssh_username=request.form.get("ssh_username", ""),
            ssh_key_path=request.form.get("ssh_key_path", ""),
            ssh_port=int(request.form.get("ssh_port", 22)),
            winrm_username=request.form.get("winrm_username", ""),
            winrm_port=int(request.form.get("winrm_port", 5986)),
            description=request.form.get("description", ""),
        )

        store = get_machine_store()
        store[machine_id] = machine
        log_event("machine_added", {"hostname": machine.hostname, "by": current_user.username})
        flash(f"Machine '{machine.hostname}' added successfully.", "success")
        return redirect(url_for("machines.index"))

    return render_template("machines/add.html")


@machines_bp.route("/delete/<machine_id>", methods=["POST"])
@login_required
def delete(machine_id):
    err = _require_admin()
    if err:
        return err

    store = get_machine_store()
    machine = store.pop(machine_id, None)
    if machine:
        log_event("machine_deleted", {"hostname": machine.hostname, "by": current_user.username})
        flash(f"Machine '{machine.hostname}' removed.", "success")
    return redirect(url_for("machines.index"))


@machines_bp.route("/test/<machine_id>")
@login_required
def test_connection(machine_id):
    """Test connectivity to a machine (AJAX endpoint)."""
    store = get_machine_store()
    machine = store.get(machine_id)
    if not machine:
        return jsonify({"status": "error", "message": "Machine not found"}), 404

    try:
        import sys, os
        sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "..", ".."))

        if machine.connection_type == "ssh":
            from core.executors.ssh_executor import SSHExecutor
            executor = SSHExecutor(
                hostname=machine.hostname,
                username=machine.ssh_username,
                key_path=machine.ssh_key_path,
                port=machine.ssh_port,
            )
        else:
            from core.executors.winrm_executor import WinRMExecutor
            executor = WinRMExecutor(
                hostname=machine.hostname,
                username=machine.winrm_username,
                port=machine.winrm_port,
            )

        success = executor.test_connection()
        executor.close()

        store[machine_id].status = "online" if success else "offline"
        return jsonify({
            "status": "online" if success else "offline",
            "message": "Connection successful" if success else "Connection failed",
        })

    except Exception as e:
        store[machine_id].status = "offline"
        return jsonify({"status": "offline", "message": str(e)}), 200
