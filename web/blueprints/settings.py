# wiperx/web/blueprints/settings.py
"""
Settings Blueprint
------------------
One page, four sections:
  - Profile      : change your own password
  - Security     : signing-key identity + download the public key
  - Integrations : read-only status of DB / LDAP / SIEM (booleans only, no secrets)
  - Users        : ADMIN only — list accounts and roles

Nothing here mutates a wipe/recovery code path; it is account and
configuration surface only.
"""

import os

from flask import (
    Blueprint, render_template, request, redirect, url_for, flash, send_file, abort,
)
from flask_login import login_required, current_user

from core import report_signer
from core.audit_logger import log_event
from web.models import get_user_store, UserRole

settings_bp = Blueprint("settings", __name__)


def _integrations() -> dict:
    return {
        "database": bool(os.environ.get("DATABASE_URL")),
        "ldap": bool(os.environ.get("WIPERX_LDAP_URL")),
        "siem_splunk": bool(os.environ.get("WIPERX_SPLUNK_HEC_URL")),
        "siem_elastic": bool(os.environ.get("WIPERX_ELASTIC_URL")),
    }


def _signing_key() -> dict:
    info = {"fingerprint": None, "path": None, "public_key_path": None, "error": None}
    try:
        path = report_signer._private_key_path()
        info["path"] = str(path)
        info["public_key_path"] = str(path.with_suffix(".pub.pem"))
        info["fingerprint"] = report_signer.signing_fingerprint()
    except Exception as exc:  # noqa: BLE001 - surfaced read-only in the UI
        info["error"] = str(exc)
    return info


@settings_bp.route("/")
@login_required
def index():
    users = None
    if current_user.can("manage_machines"):
        users = sorted(
            (u.to_dict() for u in get_user_store().values()),
            key=lambda d: (d["role"], d["username"]),
        )
    return render_template(
        "settings/index.html",
        integrations=_integrations(),
        signing_key=_signing_key(),
        users=users,
        roles=UserRole.ALL,
    )


@settings_bp.route("/password", methods=["POST"])
@login_required
def change_password():
    current = request.form.get("current_password", "")
    new = request.form.get("new_password", "")
    confirm = request.form.get("confirm_password", "")

    if not current_user.check_password(current):
        flash("Current password is incorrect.", "danger")
        return redirect(url_for("settings.index"))
    if len(new) < 8:
        flash("New password must be at least 8 characters.", "warning")
        return redirect(url_for("settings.index"))
    if new != confirm:
        flash("New password and confirmation do not match.", "warning")
        return redirect(url_for("settings.index"))

    from web.models import _make_hash

    store = get_user_store()
    user = store.get(current_user.id)
    user.password_hash = _make_hash(new)
    store[user.id] = user
    log_event("password_changed", {"username": current_user.username})
    flash("Password updated.", "success")
    return redirect(url_for("settings.index"))


@settings_bp.route("/signing-key.pub")
@login_required
def download_public_key():
    try:
        path = report_signer._private_key_path().with_suffix(".pub.pem")
    except Exception:  # noqa: BLE001
        abort(404)
    if not os.path.exists(path):
        # Generating the identity also writes the .pub.pem alongside it.
        report_signer.signing_fingerprint()
    if not os.path.exists(path):
        abort(404)
    return send_file(path, as_attachment=True, download_name="wiperx_sign_key.pub.pem")
