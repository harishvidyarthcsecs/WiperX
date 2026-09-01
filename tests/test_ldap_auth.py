"""
Tests for web/ldap_auth.py.

Two tiers, same pattern as tests/test_db_backend.py:
  - Unit tests with LDAP calls monkeypatched: always run.
  - Real OpenLDAP: only if WIPERX_TEST_LDAP_URL is set (manually verified
    during development against a real `osixia/openldap:1.5.0` container,
    including an actual search-then-bind login through the full Flask
    login flow with LDAP-group-to-role mapping and RBAC enforcement - see
    docs/ROADMAP.md - but not assumed present in a default test run).
"""

import os

import pytest

from web import ldap_auth


class TestConfigAndHelpers:
    def test_not_configured_by_default(self, monkeypatch):
        monkeypatch.delenv("WIPERX_LDAP_URL", raising=False)
        assert ldap_auth.is_configured() is False

    def test_configured_when_url_set(self, monkeypatch):
        monkeypatch.setenv("WIPERX_LDAP_URL", "ldap://example.com")
        assert ldap_auth.is_configured() is True

    def test_authenticate_returns_none_when_not_configured(self, monkeypatch):
        monkeypatch.delenv("WIPERX_LDAP_URL", raising=False)
        assert ldap_auth.authenticate("anyone", "anything") is None

    def test_authenticate_returns_none_for_empty_credentials(self, monkeypatch):
        monkeypatch.setenv("WIPERX_LDAP_URL", "ldap://example.com")
        assert ldap_auth.authenticate("", "x") is None
        assert ldap_auth.authenticate("x", "") is None

    @pytest.mark.parametrize("raw,escaped", [
        ("normal", "normal"),
        ("a*b", "a\\2ab"),
        ("a(b)c", "a\\28b\\29c"),
        ("back\\slash", "back\\5cslash"),
    ])
    def test_escape_filter_special_chars(self, raw, escaped):
        assert ldap_auth._escape(raw) == escaped

    def test_map_role_admin_group(self, monkeypatch):
        monkeypatch.setenv("WIPERX_LDAP_ADMIN_GROUP", "wiperx-admins")
        assert ldap_auth.map_role(["wiperx-admins", "other"]) == "admin"

    def test_map_role_operator_group(self, monkeypatch):
        monkeypatch.setenv("WIPERX_LDAP_ADMIN_GROUP", "wiperx-admins")
        monkeypatch.setenv("WIPERX_LDAP_OPERATOR_GROUP", "wiperx-ops")
        assert ldap_auth.map_role(["wiperx-ops"]) == "operator"

    def test_map_role_default_viewer_for_unmapped_group(self, monkeypatch):
        monkeypatch.setenv("WIPERX_LDAP_ADMIN_GROUP", "wiperx-admins")
        assert ldap_auth.map_role(["some-random-group"]) == "viewer"

    def test_map_role_admin_takes_precedence_over_operator(self, monkeypatch):
        monkeypatch.setenv("WIPERX_LDAP_ADMIN_GROUP", "wiperx-admins")
        monkeypatch.setenv("WIPERX_LDAP_OPERATOR_GROUP", "wiperx-ops")
        assert ldap_auth.map_role(["wiperx-ops", "wiperx-admins"]) == "admin"

    def test_map_role_case_insensitive(self, monkeypatch):
        monkeypatch.setenv("WIPERX_LDAP_ADMIN_GROUP", "WiperX-Admins")
        assert ldap_auth.map_role(["wiperx-admins"]) == "admin"


class TestAuthenticateErrorHandling:
    """authenticate() must never raise - an LDAP outage should just fail
    the login, not crash the request."""

    def test_ldap3_missing_returns_none(self, monkeypatch):
        monkeypatch.setenv("WIPERX_LDAP_URL", "ldap://example.com")
        monkeypatch.setattr(ldap_auth, "_LDAP3_OK", False)
        assert ldap_auth.authenticate("user", "pass") is None

    def test_unreachable_server_returns_none_not_exception(self, monkeypatch):
        monkeypatch.setenv("WIPERX_LDAP_URL", "ldap://127.0.0.1:1")  # nothing listens here
        monkeypatch.setenv("WIPERX_LDAP_USER_BASE_DN", "ou=people,dc=example,dc=com")
        # Real connection attempt to a closed port - should fail cleanly, not raise.
        result = ldap_auth.authenticate("user", "pass")
        assert result is None


@pytest.mark.skipif(
    not os.environ.get("WIPERX_TEST_LDAP_URL"),
    reason="set WIPERX_TEST_LDAP_URL (+ related WIPERX_LDAP_* vars) to run against a real LDAP server",
)
class TestRealOpenLDAP:
    @pytest.fixture(autouse=True)
    def _ldap_env(self, monkeypatch):
        monkeypatch.setenv("WIPERX_LDAP_URL", os.environ["WIPERX_TEST_LDAP_URL"])
        monkeypatch.setenv("WIPERX_LDAP_BIND_DN", os.environ["WIPERX_TEST_LDAP_BIND_DN"])
        monkeypatch.setenv("WIPERX_LDAP_BIND_PASSWORD", os.environ["WIPERX_TEST_LDAP_BIND_PASSWORD"])
        monkeypatch.setenv("WIPERX_LDAP_USER_BASE_DN", os.environ["WIPERX_TEST_LDAP_USER_BASE_DN"])
        monkeypatch.setenv("WIPERX_LDAP_GROUP_BASE_DN", os.environ["WIPERX_TEST_LDAP_GROUP_BASE_DN"])
        monkeypatch.setenv("WIPERX_LDAP_ADMIN_GROUP", "wiperx-admins")

    def test_correct_password_authenticates(self):
        user = ldap_auth.authenticate("jdoe", os.environ["WIPERX_TEST_LDAP_JDOE_PASSWORD"])
        assert user is not None
        assert user.username == "jdoe"
        assert "wiperx-admins" in user.groups

    def test_wrong_password_rejected(self):
        assert ldap_auth.authenticate("jdoe", "definitely-wrong") is None

    def test_unknown_user_rejected(self):
        assert ldap_auth.authenticate("no-such-user", "anything") is None

    def test_role_mapping_end_to_end(self):
        user = ldap_auth.authenticate("jdoe", os.environ["WIPERX_TEST_LDAP_JDOE_PASSWORD"])
        assert ldap_auth.map_role(user.groups) == "admin"
