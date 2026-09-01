# wiperx/web/models.py
"""
WiperX Web Models
-----------------
User/machine stores, backed by an in-memory dict by default (zero-config,
same as always) or by a real database when DATABASE_URL is set (see
web/db.py, web/db_models.py) - selected automatically by get_user_store()/
get_machine_store() based on web.db.is_db_enabled().

The DB-backed stores (_UserDBStore / _MachineDBStore below) implement
collections.abc.MutableMapping so every existing call site - store[key],
store[key] = value, store.pop(key), list(store.values()), store.get(key) -
keeps working unchanged regardless of which backend is active.

  - Integrate with LDAP/AD for enterprise authentication: done, see
    web/ldap_auth.py - LDAP-authenticated users are provisioned
    just-in-time into whichever user store is active (auth_source="ldap").
  - Use bcrypt for password hashing (already imported).
  - Implement proper session management with Redis: still open, see
    docs/ROADMAP.md.

Role-Based Access Control (RBAC) Design:
  - ADMIN    : Full access — scan, wipe local+remote, manage machines, download reports.
  - OPERATOR : Scan any registered machine; wipe only with confirmed target approval.
  - VIEWER   : Read-only — view scan results and reports; cannot initiate wipes.
"""

import os
import bcrypt
from collections.abc import MutableMapping
from flask_login import UserMixin
from dataclasses import dataclass
from typing import Dict, Iterator, Optional

from web import db


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
# In-Memory Stores (default; superseded by the DB-backed stores below when
# DATABASE_URL is set)
# ---------------------------------------------------------------------------

def _make_hash(password: str) -> str:
    """Generate bcrypt hash for a password."""
    return bcrypt.hashpw(password.encode("utf-8"), bcrypt.gensalt()).decode("utf-8")


def _default_users() -> Dict[str, User]:
    """The 3 demo accounts, shared by the in-memory store and the DB seed."""
    return {
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


# In-memory user store (used until/unless a DB is configured)
_USER_STORE: Dict[str, User] = _default_users()

# In-memory machine registry
_MACHINE_STORE: Dict[str, RemoteMachine] = {}


# ---------------------------------------------------------------------------
# DB-backed stores — MutableMapping so every existing call site (store[k],
# store[k]=v, store.pop(k), list(store.values()), store.get(k), k in store)
# keeps working unchanged. Only 5 methods are actually required by the ABC;
# get/pop/values/items/keys/__contains__ come from MutableMapping for free.
# ---------------------------------------------------------------------------

class _UserDBStore(MutableMapping):
    def _to_user(self, row) -> User:
        return User(
            user_id=row.id, username=row.username, password_hash=row.password_hash,
            role=row.role, display_name=row.display_name,
        )

    def __getitem__(self, key: str) -> User:
        from web.db_models import UserORM
        with db.get_session() as session:
            row = session.get(UserORM, key)
            if row is None:
                raise KeyError(key)
            return self._to_user(row)

    def __setitem__(self, key: str, user: User) -> None:
        from web.db_models import UserORM
        with db.get_session() as session:
            row = session.get(UserORM, key)
            if row is None:
                row = UserORM(id=key)
            row.username = user.username
            row.password_hash = user.password_hash
            row.role = user.role
            row.display_name = user.display_name
            session.merge(row)
            session.commit()

    def __delitem__(self, key: str) -> None:
        from web.db_models import UserORM
        with db.get_session() as session:
            row = session.get(UserORM, key)
            if row is None:
                raise KeyError(key)
            session.delete(row)
            session.commit()

    def __iter__(self) -> Iterator[str]:
        from web.db_models import UserORM
        with db.get_session() as session:
            return iter([row.id for row in session.query(UserORM.id).all()])

    def __len__(self) -> int:
        from web.db_models import UserORM
        with db.get_session() as session:
            return session.query(UserORM).count()

    def find_by_username(self, username: str) -> Optional[User]:
        from web.db_models import UserORM
        with db.get_session() as session:
            row = session.query(UserORM).filter_by(username=username).first()
            return self._to_user(row) if row else None

    def auth_source(self, username: str) -> Optional[str]:
        from web.db_models import UserORM
        with db.get_session() as session:
            row = session.query(UserORM).filter_by(username=username).first()
            return row.auth_source if row else None

    def upsert_ldap_user(self, *, user_id: str, username: str, role: str, display_name: str) -> User:
        """Just-in-time provision/update an LDAP-authenticated user."""
        from web.db_models import UserORM
        with db.get_session() as session:
            row = session.query(UserORM).filter_by(username=username).first()
            if row is None:
                row = UserORM(id=user_id, username=username)
            row.password_hash = row.password_hash or _make_hash(os.urandom(16).hex())
            row.role = role
            row.display_name = display_name
            row.auth_source = "ldap"
            session.merge(row)
            session.commit()
            return self._to_user(row)


class _MachineDBStore(MutableMapping):
    def _to_machine(self, row) -> RemoteMachine:
        return RemoteMachine(
            machine_id=row.machine_id, hostname=row.hostname, os_type=row.os_type,
            connection_type=row.connection_type, ssh_username=row.ssh_username,
            ssh_key_path=row.ssh_key_path, ssh_port=row.ssh_port,
            winrm_username=row.winrm_username, winrm_port=row.winrm_port,
            description=row.description, last_scan=row.last_scan, status=row.status,
        )

    def __getitem__(self, key: str) -> RemoteMachine:
        from web.db_models import MachineORM
        with db.get_session() as session:
            row = session.get(MachineORM, key)
            if row is None:
                raise KeyError(key)
            return self._to_machine(row)

    def __setitem__(self, key: str, machine: RemoteMachine) -> None:
        from web.db_models import MachineORM
        with db.get_session() as session:
            row = session.get(MachineORM, key) or MachineORM(machine_id=key)
            for field in (
                "hostname", "os_type", "connection_type", "ssh_username",
                "ssh_key_path", "ssh_port", "winrm_username", "winrm_port",
                "description", "last_scan", "status",
            ):
                setattr(row, field, getattr(machine, field))
            session.merge(row)
            session.commit()

    def __delitem__(self, key: str) -> None:
        from web.db_models import MachineORM
        with db.get_session() as session:
            row = session.get(MachineORM, key)
            if row is None:
                raise KeyError(key)
            session.delete(row)
            session.commit()

    def __iter__(self) -> Iterator[str]:
        from web.db_models import MachineORM
        with db.get_session() as session:
            return iter([row.machine_id for row in session.query(MachineORM.machine_id).all()])

    def __len__(self) -> int:
        from web.db_models import MachineORM
        with db.get_session() as session:
            return session.query(MachineORM).count()


def seed_default_users_if_empty() -> None:
    """Populate the DB with the 3 demo accounts on first run (DB backend only)."""
    if not db.is_db_enabled():
        return
    store = _UserDBStore()
    if len(store) > 0:
        return
    for user in _default_users().values():
        store[user.id] = user


def get_user_store():
    """dict (in-memory) or MutableMapping (DB-backed) of user_id -> User."""
    return _UserDBStore() if db.is_db_enabled() else _USER_STORE


def get_machine_store():
    """dict (in-memory) or MutableMapping (DB-backed) of machine_id -> RemoteMachine."""
    return _MachineDBStore() if db.is_db_enabled() else _MACHINE_STORE


def find_user_by_username(username: str) -> Optional[User]:
    if db.is_db_enabled():
        return _UserDBStore().find_by_username(username)
    for user in _USER_STORE.values():
        if user.username == username:
            return user
    return None


def provision_ldap_user(*, username: str, role: str, display_name: str) -> User:
    """
    Just-in-time provision/update a user authenticated via LDAP (see
    web/ldap_auth.py), regardless of which store backend is active.

    Called once per successful LDAP login so Flask-Login's user_loader
    (which reads from the same store) can load them like any other user
    on subsequent requests within the session.
    """
    if db.is_db_enabled():
        return _UserDBStore().upsert_ldap_user(
            user_id=f"ldap:{username}", username=username, role=role,
            display_name=display_name,
        )

    existing = find_user_by_username(username)
    user_id = existing.id if existing else f"ldap:{username}"
    user = User(
        user_id=user_id, username=username,
        password_hash=(existing.password_hash if existing else _make_hash(os.urandom(16).hex())),
        role=role, display_name=display_name,
    )
    _USER_STORE[user_id] = user
    return user
