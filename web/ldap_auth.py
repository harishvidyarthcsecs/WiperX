# wiperx/web/ldap_auth.py
"""
LDAP / Active Directory Authentication
-----------------------------------------
Search-then-bind authentication against an LDAP or AD directory - the
same pattern used by most enterprise SSO integrations (works for both
generic LDAP with a service account and AD, which doesn't allow binding
directly as "username" the way some simpler LDAP setups do).

Disabled by default: authenticate() returns None immediately unless
WIPERX_LDAP_URL is set, so the existing local-account login flow
(web/models.py's bcrypt-checked _USER_STORE / DB-backed store) is
completely unaffected when LDAP isn't configured.

Configuration (all via environment variables):
    WIPERX_LDAP_URL              ldap://host:389 or ldaps://host:636
    WIPERX_LDAP_BIND_DN          service account DN used to search for
                                  the user (e.g. cn=admin,dc=example,dc=com)
    WIPERX_LDAP_BIND_PASSWORD    password for the above
    WIPERX_LDAP_USER_BASE_DN     subtree to search for user entries
                                  (e.g. ou=people,dc=example,dc=com)
    WIPERX_LDAP_USER_FILTER      search filter template, default
                                  "(uid={username})" (use
                                  "(sAMAccountName={username})" for AD)
    WIPERX_LDAP_GROUP_BASE_DN    subtree to search for group entries when
                                  mapping role by group membership
                                  (defaults to WIPERX_LDAP_USER_BASE_DN's
                                  parent-adjacent "ou=groups,..." is NOT
                                  assumed - set explicitly)
    WIPERX_LDAP_ADMIN_GROUP      group cn (or full DN) whose members map
                                  to UserRole.ADMIN
    WIPERX_LDAP_OPERATOR_GROUP   group cn (or full DN) -> UserRole.OPERATOR
    WIPERX_LDAP_VIEWER_GROUP     group cn (or full DN) -> UserRole.VIEWER
                                  (a user in no mapped group gets VIEWER
                                  by default - least privilege, matching
                                  this codebase's other defaults)
"""

from __future__ import annotations

import logging
import os
from dataclasses import dataclass, field
from typing import List, Optional

logger = logging.getLogger(__name__)

try:
    from ldap3 import SUBTREE, Connection, Server
    from ldap3.core.exceptions import LDAPException

    _LDAP3_OK = True
except ImportError:  # pragma: no cover - dependency is declared in requirements.txt
    _LDAP3_OK = False


@dataclass
class LdapUser:
    username: str
    dn: str
    display_name: str
    email: str
    groups: List[str] = field(default_factory=list)


def is_configured() -> bool:
    return bool(os.environ.get("WIPERX_LDAP_URL"))


def _cfg(name: str, default: str = "") -> str:
    return os.environ.get(name, default)


def _group_matches(group_cn_or_dn: str, memberships: List[str]) -> bool:
    if not group_cn_or_dn:
        return False
    target = group_cn_or_dn.strip().lower()
    return any(target == g.strip().lower() for g in memberships)


def map_role(groups: List[str]) -> str:
    """Map LDAP group membership to a WiperX role. Least-privilege default."""
    from web.models import UserRole

    if _group_matches(_cfg("WIPERX_LDAP_ADMIN_GROUP"), groups):
        return UserRole.ADMIN
    if _group_matches(_cfg("WIPERX_LDAP_OPERATOR_GROUP"), groups):
        return UserRole.OPERATOR
    return UserRole.VIEWER


def authenticate(username: str, password: str) -> Optional[LdapUser]:
    """
    Search-then-bind authentication.

    Returns:
        LdapUser on success, None on any failure (bad credentials, LDAP
        unreachable, misconfiguration, or LDAP simply not configured at
        all) - callers should treat None as "try the next auth method or
        reject", never distinguish the reason, to avoid leaking whether a
        username exists.
    """
    if not is_configured():
        return None
    if not _LDAP3_OK:
        logger.error("[ldap_auth] WIPERX_LDAP_URL is set but ldap3 is not installed")
        return None
    if not username or not password:
        return None

    url = _cfg("WIPERX_LDAP_URL")
    user_base_dn = _cfg("WIPERX_LDAP_USER_BASE_DN")
    user_filter_template = _cfg("WIPERX_LDAP_USER_FILTER", "(uid={username})")
    group_base_dn = _cfg("WIPERX_LDAP_GROUP_BASE_DN", user_base_dn)

    try:
        server = Server(url, get_info=None)

        bind_dn = _cfg("WIPERX_LDAP_BIND_DN") or None
        bind_password = _cfg("WIPERX_LDAP_BIND_PASSWORD") or None
        service_conn = Connection(server, user=bind_dn, password=bind_password, auto_bind=True)

        user_filter = user_filter_template.format(username=_escape(username))
        service_conn.search(
            user_base_dn, user_filter, SUBTREE,
            attributes=["cn", "mail", "displayName"],
        )
        if not service_conn.entries:
            logger.info("[ldap_auth] no LDAP entry for %s", username)
            service_conn.unbind()
            return None

        entry = service_conn.entries[0]
        user_dn = entry.entry_dn
        service_conn.unbind()

        # The actual authentication check: bind AS the user with their
        # own password. A successful service-account search proves
        # nothing about the user's password.
        user_conn = Connection(server, user=user_dn, password=password)
        if not user_conn.bind():
            logger.info("[ldap_auth] bind failed for %s", username)
            return None

        display_name = (
            str(entry.displayName) if "displayName" in entry and entry.displayName
            else (str(entry.cn) if "cn" in entry and entry.cn else username)
        )
        email = str(entry.mail) if "mail" in entry and entry.mail else ""

        groups = _lookup_groups(server, bind_dn, bind_password, group_base_dn, user_dn)
        user_conn.unbind()

        return LdapUser(username=username, dn=user_dn, display_name=display_name,
                         email=email, groups=groups)

    except LDAPException as exc:
        logger.warning("[ldap_auth] LDAP error authenticating %s: %s", username, exc)
        return None
    except Exception as exc:  # noqa: BLE001 - never let an LDAP outage crash login
        logger.warning("[ldap_auth] unexpected error authenticating %s: %s", username, exc)
        return None


def _lookup_groups(server, bind_dn, bind_password, group_base_dn, user_dn) -> List[str]:
    if not group_base_dn:
        return []
    try:
        conn = Connection(server, user=bind_dn, password=bind_password, auto_bind=True)
        conn.search(group_base_dn, f"(member={_escape(user_dn)})", SUBTREE, attributes=["cn"])
        groups = [str(e.cn) for e in conn.entries if "cn" in e]
        conn.unbind()
        return groups
    except Exception as exc:  # noqa: BLE001 - group lookup failure isn't fatal to login
        logger.warning("[ldap_auth] group lookup failed for %s: %s", user_dn, exc)
        return []


def _escape(value: str) -> str:
    """Escape an LDAP filter special character to prevent filter injection."""
    return (
        value.replace("\\", "\\5c").replace("*", "\\2a")
        .replace("(", "\\28").replace(")", "\\29").replace("\x00", "\\00")
    )
