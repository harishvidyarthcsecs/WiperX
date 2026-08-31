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

import bcrypt
from flask_login import UserMixin
from dataclasses import dataclass
from typing import Dict, Optional


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
# In-Memory Stores (replace with DB in production)
# ---------------------------------------------------------------------------

def _make_hash(password: str) -> str:
    """Generate bcrypt hash for a password."""
    return bcrypt.hashpw(password.encode("utf-8"), bcrypt.gensalt()).decode("utf-8")


# Default users (for demonstration only)
# In production: load from secure database, never hardcode passwords
_USER_STORE: Dict[str, User] = {
    "1": User(
        user_id="1",
        username="admin",
        password_hash=_make_hash("admin123"),   # CHANGE IN PRODUCTION
        role=UserRole.ADMIN,
        display_name="System Administrator",
    ),
    "2": User(
        user_id="2",
        username="operator",
        password_hash=_make_hash("operator123"),
        role=UserRole.OPERATOR,
        display_name="Wipe Operator",
    ),
    "3": User(
        user_id="3",
        username="viewer",
        password_hash=_make_hash("viewer123"),
        role=UserRole.VIEWER,
        display_name="Report Viewer",
    ),
}

# In-memory machine registry
_MACHINE_STORE: Dict[str, RemoteMachine] = {}


def get_user_store() -> Dict[str, User]:
    return _USER_STORE


def get_machine_store() -> Dict[str, RemoteMachine]:
    return _MACHINE_STORE


def find_user_by_username(username: str) -> Optional[User]:
    for user in _USER_STORE.values():
        if user.username == username:
            return user
    return None
