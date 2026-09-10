# wiperx/web/blueprints/_fsroot.py
"""Shared filesystem-sandbox helpers for the web layer.

The eraser and recovery blueprints let an authenticated operator name a path on
the server's own filesystem. Left unbounded (and the README tells operators to
run the web app as root) that is an arbitrary-file-destruction / -read hole, so
every such path must resolve inside a configured *allowed root*.

`allowed_root()` fails closed: if no root is configured it falls back to the
invoking OS user's home directory and never returns the filesystem root.
"""

import os
from pathlib import Path

from flask import current_app


def allowed_root(*env_vars: str, config_keys=()) -> Path:
    """Resolve the sandbox root for a feature.

    Checks each name in ``env_vars`` (``os.environ``) then each key in
    ``config_keys`` (``current_app.config``); the first value wins. With nothing
    configured, falls back to the current user's home directory.

    Raises:
        RuntimeError: the resolved root is the filesystem root ("/"), which would
            defeat the sandbox. The operator must set one of ``env_vars``.
    """
    raw = None
    for name in env_vars:
        raw = os.environ.get(name)
        if raw:
            break
    if not raw:
        for key in config_keys:
            try:
                raw = current_app.config.get(key)
            except RuntimeError:  # no application context
                raw = None
            if raw:
                break

    root = Path(raw).resolve() if raw else Path.home().resolve()

    if root == Path(root.anchor):
        hint = env_vars[0] if env_vars else "the allowed-root env var"
        raise RuntimeError(
            f"Refusing a filesystem-root sandbox ('{root}'). "
            f"Set {hint} to a real directory before using this feature."
        )
    return root


def path_within_root(p: str, root: Path):
    """Return ``(ok, reason)`` for whether ``p`` resolves inside ``root``."""
    try:
        rp = Path(p).resolve()
    except OSError:
        return False, f"Cannot resolve path: {p}"
    if rp == root or root in rp.parents:
        return True, ""
    return False, f"Path is outside the allowed root ({root}): {p}"
