# wiperx/web/app.py
"""
WiperX Flask Application Factory
----------------------------------
Creates and configures the Flask application.
Uses Blueprint-based architecture for clean separation.

Blueprints:
  - auth      : Login / logout
  - dashboard : Overview page + audit log
  - machines  : Remote machine management
  - disks     : Disk scanning and selection
  - wipe      : Drive eraser landing, confirmation, execution
  - reports   : Report listing and download
  - eraser    : Secure file / folder eraser
  - recovery  : Forensic carving & recovery
  - settings  : Profile, signing key, integration status, users

Role-based Access:
  - ADMIN   : scan + wipe local and remote; download all reports; manage users
  - OPERATOR: scan + wipe pre-approved machines; download reports
  - VIEWER  : view reports and scan results; cannot initiate wipes

  Roles live in the User model; production integrates LDAP/AD or OAuth2.
"""

import hashlib
import logging
import os

from flask import Flask, render_template
from flask_login import LoginManager
from flask_wtf import CSRFProtect

from web.models import get_user_store, seed_default_users_if_empty
from web import db as web_db

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(name)s: %(message)s",
)

_STATIC_DIR = os.path.join(os.path.dirname(__file__), "static")

csrf = CSRFProtect()


def _asset_version() -> str:
    """Short hash of the built stylesheet, for cache-busting ?v= query strings.

    Falls back to a constant when the build output is missing so the app still
    boots in a bare checkout.
    """
    css = os.path.join(_STATIC_DIR, "css", "app.css")
    try:
        with open(css, "rb") as fh:
            return hashlib.sha256(fh.read()).hexdigest()[:12]
    except OSError:
        return "dev"


def create_app(config_override: dict = None) -> Flask:
    """Flask application factory."""
    app = Flask(
        __name__,
        template_folder="templates",
        static_folder="static",
    )

    # ── Configuration ──
    app.config.update({
        "SECRET_KEY": os.environ.get("WIPERX_SECRET_KEY", "change-me-in-production-use-env-var"),
        "SESSION_COOKIE_HTTPONLY": True,
        "SESSION_COOKIE_SAMESITE": "Lax",
        "SESSION_COOKIE_SECURE": os.environ.get("WIPERX_HTTPS", "false").lower() == "true",
        "MAX_CONTENT_LENGTH": 16 * 1024 * 1024,  # 16MB max upload
        "REPORTS_DIR": os.path.join(os.path.dirname(__file__), "..", "reports"),
        "ASSET_VERSION": _asset_version(),
    })

    if config_override:
        app.config.update(config_override)

    # ── CSRF (Flask-WTF) — every POST form carries a token; GET/HEAD exempt.
    #    tests disable it via WTF_CSRF_ENABLED=False in conftest.py. ──
    csrf.init_app(app)

    # ── Database (optional — DATABASE_URL unset means in-memory stores) ──
    database_url = app.config.get("DATABASE_URL") or os.environ.get("DATABASE_URL")
    if database_url:
        web_db.init_db(database_url)
        seed_default_users_if_empty()

    # ── Flask-Login ──
    login_manager = LoginManager()
    login_manager.init_app(app)
    login_manager.login_view = "auth.login"
    login_manager.login_message = "Please log in to access WiperX."
    login_manager.login_message_category = "warning"

    @login_manager.user_loader
    def load_user(user_id: str):
        store = get_user_store()
        return store.get(user_id)

    # ── Blueprints ──
    from web.blueprints.auth import auth_bp
    from web.blueprints.dashboard import dashboard_bp
    from web.blueprints.machines import machines_bp
    from web.blueprints.disks import disks_bp
    from web.blueprints.wipe import wipe_bp
    from web.blueprints.reports import reports_bp
    from web.blueprints.eraser import eraser_bp
    from web.blueprints.recovery import recovery_bp
    from web.blueprints.settings import settings_bp

    app.register_blueprint(auth_bp, url_prefix="/auth")
    app.register_blueprint(dashboard_bp, url_prefix="/")
    app.register_blueprint(machines_bp, url_prefix="/machines")
    app.register_blueprint(disks_bp, url_prefix="/disks")
    app.register_blueprint(wipe_bp, url_prefix="/wipe")
    app.register_blueprint(reports_bp, url_prefix="/reports")
    app.register_blueprint(eraser_bp, url_prefix="/eraser")
    app.register_blueprint(recovery_bp, url_prefix="/recovery")
    app.register_blueprint(settings_bp, url_prefix="/settings")

    _register_template_helpers(app)
    _register_security_headers(app)
    _register_error_handlers(app)

    return app


def _register_template_helpers(app: Flask) -> None:
    from flask import url_for
    from flask_wtf.csrf import generate_csrf

    def asset(path: str) -> str:
        return url_for("static", filename=path, v=app.config["ASSET_VERSION"])

    # Registered as Jinja globals (not context processors) so they are also
    # available inside macros imported without `with context`.
    app.jinja_env.globals["asset"] = asset
    app.jinja_env.globals["csrf_token"] = generate_csrf


def _register_security_headers(app: Flask) -> None:
    # CSP: only self-hosted assets. 'unsafe-inline' for style is kept because a
    # handful of templates set inline width/height on progress elements; scripts
    # are strictly self. connect-src 'self' covers the SSE log streams.
    csp = (
        "default-src 'self'; "
        "script-src 'self'; "
        "style-src 'self' 'unsafe-inline'; "
        "img-src 'self' data:; "
        "font-src 'self'; "
        "connect-src 'self'; "
        "frame-ancestors 'none'; "
        "base-uri 'self'; "
        "form-action 'self'"
    )

    @app.after_request
    def _headers(resp):
        resp.headers.setdefault("Content-Security-Policy", csp)
        resp.headers.setdefault("X-Content-Type-Options", "nosniff")
        resp.headers.setdefault("X-Frame-Options", "DENY")
        resp.headers.setdefault("Referrer-Policy", "same-origin")
        resp.headers.setdefault("Permissions-Policy", "geolocation=(), microphone=(), camera=()")
        return resp


def _register_error_handlers(app: Flask) -> None:
    @app.errorhandler(403)
    def _403(e):
        return render_template("errors/403.html"), 403

    @app.errorhandler(404)
    def _404(e):
        return render_template("errors/404.html"), 404

    @app.errorhandler(500)
    def _500(e):
        return render_template("errors/500.html"), 500
