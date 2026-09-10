# wiperx/web/blueprints/browse.py
"""
Browse Blueprint
----------------
Read-only directory listing that backs the erase / recovery location pickers.

Safety:
  - Requires the "wipe" permission (ADMIN / OPERATOR).
  - Every listed path resolves inside the shared filesystem sandbox
    (web/blueprints/_fsroot.py): WIPERX_BROWSE_ROOT, else the erase / recover
    root, else the OS user's home - never "/".
  - Returns names + metadata only, never file contents.
"""

import os
from pathlib import Path

from flask import Blueprint, jsonify, request
from flask_login import current_user, login_required

from web.blueprints._fsroot import allowed_root, path_within_root

browse_bp = Blueprint("browse", __name__)


def _browse_root() -> Path:
    """The picker sandbox root - always a real directory (fails closed)."""
    return allowed_root(
        "WIPERX_BROWSE_ROOT",
        "WIPERX_ERASE_ALLOWED_ROOT",
        "WIPERX_RECOVER_ALLOWED_ROOT",
        config_keys=("BROWSE_ROOT", "ERASE_ALLOWED_ROOT", "RECOVER_ALLOWED_ROOT"),
    )


@browse_bp.route("/list")
@login_required
def list_dir():
    """List one directory inside the sandbox as JSON."""
    if not current_user.can("wipe"):
        return jsonify({"error": "Access denied: wipe permission required."}), 403

    root = _browse_root()
    raw = (request.args.get("path") or "").strip()

    if raw:
        if ".." in Path(raw).parts:
            return jsonify({"error": "Path traversal ('..') is not allowed."}), 400
        try:
            cwd = Path(raw).resolve()
        except OSError:
            return jsonify({"error": f"Cannot resolve path: {raw}"}), 400
        ok, reason = path_within_root(str(cwd), root)
        if not ok:
            return jsonify({"error": reason}), 403
    else:
        cwd = root

    if not cwd.is_dir():
        return jsonify({"error": f"Not a directory: {cwd}"}), 404

    try:
        scanned = list(os.scandir(cwd))
    except OSError as exc:
        return jsonify({"error": f"Cannot read directory: {exc}"}), 403

    entries = []
    for entry in scanned:
        try:
            is_dir = entry.is_dir()
            stat = entry.stat()
        except OSError:
            continue
        entries.append({
            "name": entry.name,
            "path": entry.path,
            "is_dir": is_dir,
            "size": None if is_dir else stat.st_size,
            "mtime": stat.st_mtime,
        })

    entries.sort(key=lambda d: (not d["is_dir"], d["name"].lower()))

    return jsonify({
        "root": str(root),
        "cwd": str(cwd),
        "parent": None if cwd == root else str(cwd.parent),
        "entries": entries,
    })
