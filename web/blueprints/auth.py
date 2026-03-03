# wiperx/web/blueprints/auth.py
"""Auth Blueprint — Login and logout routes."""

from flask import Blueprint, render_template, redirect, url_for, flash, request
from flask_login import login_user, logout_user, login_required, current_user
from web.models import find_user_by_username
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
        if user and user.check_password(password):
            login_user(user, remember=False)
            log_event("user_login", {"username": username, "ip": request.remote_addr})
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
