#!/usr/bin/env python3
# run.py — WiperX Flask Application Entry Point
"""
Start WiperX Flask web application.

Usage:
    python run.py                  # Development mode
    python run.py --host 0.0.0.0   # Bind to all interfaces
    python run.py --port 8080      # Custom port

Production deployment:
    gunicorn -w 4 -b 0.0.0.0:5000 "run:create_app()"

Environment variables:
    WIPERX_SECRET_KEY   : Flask secret key (required in production)
    WIPERX_HTTPS        : Set to "true" for secure cookie flag
    WIPERX_SSH_KEY_PATH : Default SSH private key path
    WIPERX_WINRM_PASS   : WinRM password for remote Windows targets
    WIPERX_WINRM_USER   : WinRM username for remote Windows targets
"""

import sys
import os
import argparse
import logging

# Add project root to Python path
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from web.app import create_app

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(name)s: %(message)s"
)

if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="WiperX Flask Web App")
    parser.add_argument("--host", default="127.0.0.1", help="Bind host (default: 127.0.0.1)")
    parser.add_argument("--port", type=int, default=5000, help="Bind port (default: 5000)")
    parser.add_argument("--debug", action="store_true", help="Enable Flask debug mode")
    args = parser.parse_args()

    if os.environ.get("WIPERX_SECRET_KEY") is None:
        print("WARNING: WIPERX_SECRET_KEY not set. Using default key (insecure for production).")

    app = create_app()

    print(f"""
╔════════════════════════════════════════╗
║  WiperX Web Application                ║
║  http://{args.host}:{args.port}         ║
║  Default login: admin / admin123       ║
╚════════════════════════════════════════╝
    """)

    app.run(host=args.host, port=args.port, debug=args.debug, threaded=True)


def create_app_factory():
    """Factory function for production WSGI servers."""
    return create_app()
