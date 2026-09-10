# wiperx/web/models.py
"""
WiperX Web Models
-----------------
Simple in-memory user store for demonstration.

In production:
  - Replace with a proper database (PostgreSQL + SQLAlchemy).
  - Integrate with LDAP/AD for enterprise authentication.
  - Use bcrypt for password hashing (already imported).
  - Implement proper session management with Redis.

Role-Based Access Control (RBAC) Design:
  - ADMIN    : Full access — scan, wipe local+remote, manage machines, download reports.
  - OPERATOR : Scan any registered machine; wipe only with confirmed target approval.
  - VIEWER   : Read-only — view scan results and reports; cannot initiate wipes.
"""

import json
import logging
import os
import secrets
from pathlib import Path

import bcrypt
from flask_login import UserMixin
from dataclasses import asdict, dataclass
from typing import Dict, Optional

logger = logging.getLogger(__name__)


class UserRole:
    ADMIN = "admin"
    OPERATOR = "operator"
    VIEWER = "viewer"

    ALL = [ADMIN, OPERATOR, VIEWER]

    # Permissions mapping
    PERMISSIONS = {
        ADMIN: ["scan", "wipe", "recover", "manage_machines", "download_reports", "view_logs"],
        OPERATOR: ["scan", "wipe", "recover", "download_reports"],
        VIEWER: ["scan", "download_reports"],
    }

    @classmethod
    def can(cls, role: str, action: str) -> bool:
        return action in cls.PERMISSIONS.get(role, [])


class User(UserMixin):
    """
    WiperX user object. Implements Flask-Login UserMixin.
    """

    def __init__(
        self,
        user_id: str,
        username: str,
        password_hash: str,
        role: str = UserRole.VIEWER,
        display_name: str = "",
    ):
        self.id = user_id
        self.username = username
        self.password_hash = password_hash
        self.role = role
        self.display_name = display_name or username

    def check_password(self, password: str) -> bool:
        """Verify a password against the stored bcrypt hash."""
        return bcrypt.checkpw(
            password.encode("utf-8"),
            self.password_hash.encode("utf-8"),
        )

    def can(self, action: str) -> bool:
        """Check if this user has permission for an action."""
        return UserRole.can(self.role, action)

    def to_dict(self) -> dict:
        return {
            "id": self.id,
            "username": self.username,
            "role": self.role,
            "display_name": self.display_name,
        }


@dataclass
class RemoteMachine:
    """Represents a registered remote machine."""
    machine_id: str
    hostname: str
    os_type: str = "unknown"        # "linux" | "windows" | "unknown"
    connection_type: str = "ssh"    # "ssh" | "winrm"
    ssh_username: str = ""
    ssh_key_path: str = ""
    ssh_port: int = 22
    winrm_username: str = ""
    winrm_port: int = 5986
    description: str = ""
    last_scan: Optional[str] = None
    status: str = "unknown"         # "online" | "offline" | "unknown"


# ---------------------------------------------------------------------------
# Stores — in-memory by default; opt-in JSON persistence via WIPERX_STATE_DIR
# ---------------------------------------------------------------------------
#
# Unset WIPERX_STATE_DIR  -> pure in-memory (lost on restart, divergent across
#                            gunicorn workers). This is the demo default.
# Set WIPERX_STATE_DIR=DIR -> the user + machine stores load from and are
#                            flushed to DIR/users.json and DIR/machines.json on
#                            every mutation. A single shared file is good enough
#                            for a single-host multi-worker lab deployment; it is
#                            NOT safe for concurrent writers on network storage.
# All failures fall back to in-memory with a warning — never a failed import.


def _state_dir() -> Optional[Path]:
    """The configured persistence directory, or None (fail soft to in-memory)."""
    raw = os.environ.get("WIPERX_STATE_DIR")
    if not raw:
        return None
    path = Path(raw).expanduser()
    try:
        path.mkdir(parents=True, exist_ok=True)
    except OSError as exc:
        logger.warning(
            "WIPERX_STATE_DIR=%s is unusable (%s) - staying in-memory.", raw, exc
        )
        return None
    return path


def _user_to_dict(user: "User") -> dict:
    return {
        "id": user.id,
        "username": user.username,
        "password_hash": user.password_hash,
        "role": user.role,
        "display_name": user.display_name,
    }


def _user_from_dict(data: dict) -> "User":
    return User(
        user_id=data["id"],
        username=data["username"],
        password_hash=data["password_hash"],
        role=data.get("role", UserRole.VIEWER),
        display_name=data.get("display_name", ""),
    )


def _flush(name: str, store: dict) -> None:
    """Atomically write `store` to <state dir>/<name>.json; no-op if unconfigured."""
    state = _state_dir()
    if state is None:
        return
    if name == "machines":
        data = {k: asdict(v) for k, v in store.items()}
    else:  # "users"
        data = {k: _user_to_dict(v) for k, v in store.items()}
    path = state / f"{name}.json"
    tmp = path.with_name(path.name + ".tmp")
    try:
        tmp.write_text(json.dumps(data, indent=2), encoding="utf-8")
        os.replace(tmp, path)
    except OSError as exc:
        logger.warning("Could not persist the %s store to %s: %s", name, path, exc)


class _PersistentDict(dict):
    """A dict that flushes to disk after every mutation (see _flush)."""

    def __init__(self, name: str, *args, **kwargs):
        self._name = name
        super().__init__(*args, **kwargs)

    def _persist(self) -> None:
        _flush(self._name, self)

    def __setitem__(self, key, value):
        super().__setitem__(key, value)
        self._persist()

    def __delitem__(self, key):
        super().__delitem__(key)
        self._persist()

    def pop(self, *args):
        result = super().pop(*args)
        self._persist()
        return result

    def popitem(self):
        result = super().popitem()
        self._persist()
        return result

    def clear(self):
        super().clear()
        self._persist()

    def update(self, *args, **kwargs):
        super().update(*args, **kwargs)
        self._persist()

    def setdefault(self, *args, **kwargs):
        result = super().setdefault(*args, **kwargs)
        self._persist()
        return result


def _make_hash(password: str) -> str:
    """Generate bcrypt hash for a password."""
    return bcrypt.hashpw(password.encode("utf-8"), bcrypt.gensalt()).decode("utf-8")


def _seed_password(env_var: str, username: str) -> str:
    """
    Seed password for a built-in demo user: from `env_var` if set, otherwise a
    fresh random string logged once. Never a hardcoded literal.
    """
    pw = os.environ.get(env_var)
    if pw:
        return pw
    pw = secrets.token_urlsafe(12)
    logger.warning(
        "%s not set - generated a random password for '%s': %s "
        "(in-memory demo store; set %s / use a real user database for anything real).",
        env_var, username, pw, env_var,
    )
    return pw


# Built-in demo users. Passwords come from the environment (see .env.example)
# and are random if unset. Without WIPERX_STATE_DIR the store resets every
# process; with it, the seeded trio (hashes included) is persisted so a restart
# keeps the same generated passwords.
def _seed_users() -> Dict[str, User]:
    return {
        "1": User(
            user_id="1",
            username="admin",
            password_hash=_make_hash(_seed_password("WIPERX_ADMIN_PASSWORD", "admin")),
            role=UserRole.ADMIN,
            display_name="System Administrator",
        ),
        "2": User(
            user_id="2",
            username="operator",
            password_hash=_make_hash(
                _seed_password("WIPERX_OPERATOR_PASSWORD", "operator")
            ),
            role=UserRole.OPERATOR,
            display_name="Wipe Operator",
        ),
        "3": User(
            user_id="3",
            username="viewer",
            password_hash=_make_hash(_seed_password("WIPERX_VIEWER_PASSWORD", "viewer")),
            role=UserRole.VIEWER,
            display_name="Report Viewer",
        ),
    }


def _load_json(name: str):
    """Return the parsed <state dir>/<name>.json, or None if absent/unusable."""
    state = _state_dir()
    if state is None:
        return None
    path = state / f"{name}.json"
    if not path.exists():
        return None
    try:
        raw = json.loads(path.read_text(encoding="utf-8"))
        return raw if isinstance(raw, dict) else None
    except (OSError, ValueError) as exc:
        logger.warning("Ignoring unreadable %s store %s: %s", name, path, exc)
        return None


def _build_user_store() -> "_PersistentDict":
    raw = _load_json("users")
    if raw:
        try:
            restored = {k: _user_from_dict(v) for k, v in raw.items()}
            return _PersistentDict("users", restored)
        except (KeyError, TypeError) as exc:
            logger.warning("users.json is malformed (%s) - reseeding.", exc)
    store = _PersistentDict("users", _seed_users())
    store._persist()  # write the seed so subsequent restarts are stable
    return store


def _build_machine_store() -> "_PersistentDict":
    raw = _load_json("machines")
    restored: Dict[str, RemoteMachine] = {}
    if raw:
        try:
            restored = {k: RemoteMachine(**v) for k, v in raw.items()}
        except TypeError as exc:
            logger.warning("machines.json is malformed (%s) - starting empty.", exc)
    return _PersistentDict("machines", restored)


_USER_STORE: Dict[str, User] = _build_user_store()
_MACHINE_STORE: Dict[str, RemoteMachine] = _build_machine_store()


def get_user_store() -> Dict[str, User]:
    return _USER_STORE


def get_machine_store() -> Dict[str, RemoteMachine]:
    return _MACHINE_STORE


def find_user_by_username(username: str) -> Optional[User]:
    for user in _USER_STORE.values():
        if user.username == username:
            return user
    return None
