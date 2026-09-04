#!/usr/bin/env python3
# run.py — WiperX Flask Application Entry Point
"""
Start WiperX Flask web application.

Usage:
    python run.py                  # requires WIPERX_SECRET_KEY
    python run.py --debug          # throwaway dev key, debug reloader
    python run.py --host 0.0.0.0 --port 8080

Production deployment:
    gunicorn -w 4 -b 0.0.0.0:5000 "run:create_app_factory()"

Environment variables (see .env.example):
    WIPERX_SECRET_KEY   : Flask secret key (REQUIRED unless --debug)
    WIPERX_HTTPS        : "true" for the secure-cookie flag
    WIPERX_SSH_KEY_PATH : Default SSH private key path
    WIPERX_WINRM_USER   : WinRM username for remote Windows targets
    WIPERX_WINRM_PASS   : WinRM password for remote Windows targets
    WIPERX_ADMIN_PASSWORD / WIPERX_OPERATOR_PASSWORD / WIPERX_VIEWER_PASSWORD
                        : Demo-store passwords (random if unset)
"""

import sys
import os
import argparse
import logging

# Add project root to Python path
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

# Load a local .env before importing the app (which reads os.environ).
try:
    from dotenv import load_dotenv

    load_dotenv()
except Exception:  # noqa: BLE001
    pass

from web.app import create_app

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(name)s: %(message)s",
)


def create_app_factory():
    """Factory for production WSGI servers: gunicorn "run:create_app_factory()"."""
    return create_app()


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="WiperX Flask Web App")
    parser.add_argument("--host", default="127.0.0.1", help="Bind host (default: 127.0.0.1)")
    parser.add_argument("--port", type=int, default=5000, help="Bind port (default: 5000)")
    parser.add_argument("--debug", action="store_true", help="Enable Flask debug mode")
    args = parser.parse_args()

    if not os.environ.get("WIPERX_SECRET_KEY") and not args.debug:
        print("ERROR: WIPERX_SECRET_KEY is not set. Export it (see .env.example) "
              "or pass --debug for a throwaway dev key.", file=sys.stderr)
        sys.exit(1)

    app = create_app({"DEBUG": True} if args.debug else None)

    print(f"""
╔════════════════════════════════════════╗
║  WiperX Web Application                ║
║  http://{args.host}:{args.port}         ║
║  Login: see WIPERX_*_PASSWORD env vars ║
╚════════════════════════════════════════╝
    """)

    app.run(host=args.host, port=args.port, debug=args.debug, threaded=True)
