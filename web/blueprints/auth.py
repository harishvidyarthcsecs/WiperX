# wiperx/web/blueprints/auth.py
"""
Auth Blueprint — Login and logout routes.

Login tries the local (bcrypt) account first - so the existing demo
accounts and any local-only accounts always work, LDAP outages never
lock out a break-glass admin - then falls back to LDAP if configured
(web/ldap_auth.py) and the local check didn't succeed. A successful LDAP
bind just-in-time provisions/updates a local user record so subsequent
requests load through Flask-Login exactly like any other account.
"""

from flask import Blueprint, render_template, redirect, url_for, flash, request
from flask_login import login_user, logout_user, login_required, current_user
from web import ldap_auth
from web.models import find_user_by_username, provision_ldap_user
from core.audit_logger import log_event

auth_bp = Blueprint("auth", __name__)


@auth_bp.route("/login", methods=["GET", "POST"])
def login():
    if current_user.is_authenticated:
        return redirect(url_for("dashboard.index"))

    if request.method == "POST":
        username = request.form.get("username", "").strip()
        password = request.form.get("password", "")

        user = find_user_by_username(username)
        auth_method = None

        if user and user.check_password(password):
            auth_method = "local"
        elif ldap_auth.is_configured():
            ldap_user = ldap_auth.authenticate(username, password)
            if ldap_user:
                role = ldap_auth.map_role(ldap_user.groups)
                user = provision_ldap_user(
                    username=ldap_user.username, role=role,
                    display_name=ldap_user.display_name,
                )
                auth_method = "ldap"

        if user and auth_method:
            login_user(user, remember=False)
            log_event("user_login", {
                "username": username, "ip": request.remote_addr, "method": auth_method,
            })
            flash(f"Welcome, {user.display_name}!", "success")
            next_page = request.args.get("next")
            return redirect(next_page or url_for("dashboard.index"))
        else:
            log_event("login_failed", {"username": username, "ip": request.remote_addr})
            flash("Invalid username or password.", "danger")

    return render_template("auth/login.html")


@auth_bp.route("/logout")
@login_required
def logout():
    log_event("user_logout", {"username": current_user.username})
    logout_user()
    flash("You have been logged out.", "info")
    return redirect(url_for("auth.login"))
