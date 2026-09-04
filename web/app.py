# wiperx/web/app.py
"""
WiperX Flask Application Factory
----------------------------------
Creates and configures the Flask application.
Uses Blueprint-based architecture for clean separation.

Blueprints:
  - auth      : Login / logout
  - dashboard : Overview page
  - machines  : Remote machine management
  - disks     : Disk scanning and selection
  - wipe      : Wipe execution and confirmation
  - reports   : Report listing and download

Role-based Access (Design Level):
  - ADMIN  : Can scan + wipe local and remote; download all reports.
  - OPERATOR: Can scan + wipe pre-approved machines only.
  - VIEWER : Can view reports and scan results; cannot initiate wipes.

  In this implementation, roles are stored in the User model.
  In production, integrate with LDAP/Active Directory or OAuth2.
"""

import os
import logging
import secrets

from flask import Flask
from flask_login import LoginManager

# Load a local .env before anything reads os.environ. No-op if unavailable.
try:
    from dotenv import load_dotenv

    load_dotenv()
except Exception:  # noqa: BLE001
    pass

from web.models import get_user_store

logger = logging.getLogger(__name__)

# Configure structured logging
logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(name)s: %(message)s",
)


def create_app(config_override: dict = None) -> Flask:
    """
    Flask application factory.

    Args:
        config_override : Optional dict to override configuration values.

    Returns:
        Flask: Configured Flask application instance.
    """
    app = Flask(
        __name__,
        template_folder="templates",
        static_folder="static",
    )

    # ── Configuration ──
    _ov = config_override or {}
    _testing = bool(_ov.get("TESTING")) or bool(_ov.get("DEBUG")) or app.debug
    _secret = os.environ.get("WIPERX_SECRET_KEY")
    if not _secret:
        if _testing:
            _secret = secrets.token_hex(32)
            logger.warning(
                "WIPERX_SECRET_KEY not set - using an ephemeral key "
                "(fine for tests/dev, sessions reset on restart)."
            )
        else:
            raise RuntimeError(
                "WIPERX_SECRET_KEY must be set for a non-debug run. "
                "Export it (see .env.example) before starting WiperX."
            )

    app.config.update({
        "SECRET_KEY": _secret,
        "SESSION_COOKIE_HTTPONLY": True,
        "SESSION_COOKIE_SAMESITE": "Lax",
        "SESSION_COOKIE_SECURE": os.environ.get("WIPERX_HTTPS", "false").lower() == "true",
        "MAX_CONTENT_LENGTH": 16 * 1024 * 1024,  # 16MB max upload
        "REPORTS_DIR": os.path.join(os.path.dirname(__file__), "..", "reports"),
    })

    if config_override:
        app.config.update(config_override)

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

    # ── Register Blueprints ──
    from web.blueprints.auth import auth_bp
    from web.blueprints.dashboard import dashboard_bp
    from web.blueprints.machines import machines_bp
    from web.blueprints.disks import disks_bp
    from web.blueprints.wipe import wipe_bp
    from web.blueprints.reports import reports_bp
    from web.blueprints.eraser import eraser_bp
    from web.blueprints.recovery import recovery_bp

    app.register_blueprint(auth_bp, url_prefix="/auth")
    app.register_blueprint(dashboard_bp, url_prefix="/")
    app.register_blueprint(machines_bp, url_prefix="/machines")
    app.register_blueprint(disks_bp, url_prefix="/disks")
    app.register_blueprint(wipe_bp, url_prefix="/wipe")
    app.register_blueprint(reports_bp, url_prefix="/reports")
    app.register_blueprint(eraser_bp, url_prefix="/eraser")
    app.register_blueprint(recovery_bp, url_prefix="/recovery")

    return app
