# wiperx/web/blueprints/wipe.py
"""
Wipe Blueprint
--------------
Handles wipe confirmation, execution, and live log streaming via SSE.
"""

import json
import queue
import threading
from flask import (
    Blueprint, render_template, request, redirect,
    url_for, flash, session, Response, stream_with_context, jsonify
)
from flask_login import login_required, current_user
from core.execution_manager import ExecutionManager, ExecutionMode, RemoteConnectionConfig, WipeRequest
from core.audit_logger import log_event

wipe_bp = Blueprint("wipe", __name__)

# In-memory queue for streaming logs per session
_wipe_queues: dict = {}


@wipe_bp.route("/confirm", methods=["GET", "POST"])
@login_required
def confirm():
    """Wipe confirmation page — first and second confirmation."""
    if not current_user.can("wipe"):
        flash("Access denied: Wipe permission required.", "danger")
        return redirect(url_for("dashboard.index"))

    disk_id = request.args.get("disk_id") or request.form.get("disk_id")
    machine_id = request.args.get("machine_id", "local")
    target_label = request.args.get("target", "Local Machine")

    if request.method == "POST":
        # Collect form data
        confirmed_name = request.form.get("confirm_name", "").strip()
        second_confirm = request.form.get("second_confirm", "")
        operator = request.form.get("operator", current_user.username)

        if second_confirm != "WIPE":
            flash("You must type 'WIPE' exactly to confirm.", "danger")
            return render_template(
                "wipe/confirm.html",
                disk_id=disk_id,
                machine_id=machine_id,
                target_label=target_label,
            )

        # Store pending wipe parameters in session (not in URL — security)
        session["pending_wipe"] = {
            "disk_id": disk_id,
            "confirmed_name": confirmed_name,
            "machine_id": machine_id,
            "operator": operator,
        }

        log_event("wipe_confirmed_web", {
            "user": current_user.username,
            "disk": disk_id,
            "machine": machine_id,
        })

        return redirect(url_for("wipe.execute_wipe"))

    return render_template(
        "wipe/confirm.html",
        disk_id=disk_id,
        machine_id=machine_id,
        target_label=target_label,
    )


@wipe_bp.route("/execute")
@login_required
def execute_wipe():
    """Wipe execution page — shows live log stream."""
    if not current_user.can("wipe"):
        flash("Access denied.", "danger")
        return redirect(url_for("dashboard.index"))

    pending = session.get("pending_wipe")
    if not pending:
        flash("No pending wipe operation found.", "warning")
        return redirect(url_for("dashboard.index"))

    return render_template("wipe/execute.html", pending=pending)


@wipe_bp.route("/run", methods=["POST"])
@login_required
def run_wipe():
    """
    Background wipe endpoint.
    Runs wipe in a separate thread and streams logs via SSE.
    """
    if not current_user.can("wipe"):
        return jsonify({"error": "Access denied"}), 403

    pending = session.get("pending_wipe")
    if not pending:
        return jsonify({"error": "No pending wipe"}), 400

    session_id = current_user.id
    log_queue = queue.Queue()
    _wipe_queues[session_id] = log_queue

    def run_in_thread():
        from web.models import get_machine_store
        manager = ExecutionManager()

        machine_id = pending["machine_id"]
        exec_mode = ExecutionMode.LOCAL
        remote_config = None

        if machine_id != "local":
            store = get_machine_store()
            machine = store.get(machine_id)
            if machine:
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

        def log_cb(msg):
            log_queue.put({"type": "log", "message": msg})

        wipe_request = WipeRequest(
            disk_identifier=pending["disk_id"],
            confirmed_disk_name=pending["confirmed_name"],
            mode=exec_mode,
            remote_config=remote_config,
            log_callback=log_cb,
        )

        result = manager.execute_wipe(wipe_request)

        # Generate reports
        from core.report_generator import ReportGenerator
        reporter = ReportGenerator()
        json_path = reporter.generate_json_report(result, operator=pending.get("operator", "web"))
        pdf_path = reporter.generate_pdf_report(result, operator=pending.get("operator", "web"))

        log_queue.put({
            "type": "done",
            "success": result.success,
            "error": result.error,
            "json_report": str(json_path),
            "pdf_report": str(pdf_path) if pdf_path else None,
        })

    thread = threading.Thread(target=run_in_thread, daemon=True)
    thread.start()

    return jsonify({"status": "started"})


@wipe_bp.route("/stream/<session_id>")
@login_required
def stream_logs(session_id):
    """
    Server-Sent Events endpoint for real-time log streaming.
    Browser polls this during wipe execution.
    """

    def generate():
        q = _wipe_queues.get(current_user.id)
        if not q:
            yield f"data: {json.dumps({'type': 'error', 'message': 'No active wipe'})}\n\n"
            return

        while True:
            try:
                item = q.get(timeout=30)
                yield f"data: {json.dumps(item)}\n\n"
                if item.get("type") == "done":
                    _wipe_queues.pop(current_user.id, None)
                    break
            except queue.Empty:
                yield f"data: {json.dumps({'type': 'heartbeat'})}\n\n"

    return Response(
        stream_with_context(generate()),
        content_type="text/event-stream",
        headers={
            "Cache-Control": "no-cache",
            "X-Accel-Buffering": "no",
        },
    )
