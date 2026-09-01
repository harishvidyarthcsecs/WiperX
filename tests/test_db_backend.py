"""
Tests for the optional SQLAlchemy-backed user/machine stores (web/db.py,
web/db_models.py, and the DB-backed proxies in web/models.py).

Two tiers:
  - SQLite in-memory: always run, no external service needed.
  - Real PostgreSQL: only runs if WIPERX_TEST_POSTGRES_URL is set (this was
    manually verified against a real `postgres:16-alpine` container during
    development - see docs/ROADMAP.md - but a fixed URL isn't assumed here
    so the suite stays green without Docker access).
"""

import os

import pytest

from web import db
from web.models import (
    RemoteMachine, User, UserRole, find_user_by_username,
    get_machine_store, get_user_store, seed_default_users_if_empty,
)


@pytest.fixture
def sqlite_db():
    db.init_db("sqlite:///:memory:")
    yield
    db.reset_db_state_for_tests()


class TestSQLiteBackend:
    def test_disabled_by_default(self):
        assert db.is_db_enabled() is False
        assert isinstance(get_user_store(), dict)

    def test_enabled_after_init(self, sqlite_db):
        assert db.is_db_enabled() is True
        assert not isinstance(get_user_store(), dict)

    def test_seed_creates_three_users_once(self, sqlite_db):
        seed_default_users_if_empty()
        store = get_user_store()
        assert len(store) == 3
        seed_default_users_if_empty()  # second call must not duplicate
        assert len(get_user_store()) == 3

    def test_seeded_admin_password_checks_out(self, sqlite_db):
        seed_default_users_if_empty()
        admin = find_user_by_username("admin")
        assert admin is not None
        assert admin.role == UserRole.ADMIN
        assert admin.check_password("admin123") is True
        assert admin.check_password("wrong") is False

    def test_user_crud_roundtrip(self, sqlite_db):
        store = get_user_store()
        u = User(user_id="u1", username="bob", password_hash="hash", role=UserRole.VIEWER)
        store["u1"] = u

        fresh = get_user_store()  # new proxy instance - must read the same DB
        assert fresh["u1"].username == "bob"
        assert "u1" in fresh
        assert len(fresh) == 1

        del fresh["u1"]
        assert "u1" not in get_user_store()

    def test_missing_user_raises_keyerror(self, sqlite_db):
        with pytest.raises(KeyError):
            get_user_store()["does-not-exist"]

    def test_machine_crud_roundtrip(self, sqlite_db):
        store = get_machine_store()
        m = RemoteMachine(machine_id="m1", hostname="host1", ssh_username="root")
        store["m1"] = m

        fresh = get_machine_store()
        assert fresh["m1"].hostname == "host1"
        assert [x.hostname for x in fresh.values()] == ["host1"]

        fresh["m1"].status  # dataclass attribute access still works after round trip
        popped = fresh.pop("m1")
        assert popped.hostname == "host1"
        assert len(get_machine_store()) == 0

    def test_ldap_jit_provisioning(self, sqlite_db):
        from web.models import _UserDBStore

        store = _UserDBStore()
        user = store.upsert_ldap_user(
            user_id="ldap:jdoe", username="jdoe", role=UserRole.OPERATOR,
            display_name="Jane Doe",
        )
        assert user.username == "jdoe"
        assert store.auth_source("jdoe") == "ldap"

        # a second login updates the same row rather than creating a duplicate
        store.upsert_ldap_user(
            user_id="ldap:jdoe", username="jdoe", role=UserRole.ADMIN,
            display_name="Jane Doe",
        )
        assert len(store) == 1
        assert find_user_by_username("jdoe").role == UserRole.ADMIN


@pytest.mark.skipif(
    not os.environ.get("WIPERX_TEST_POSTGRES_URL"),
    reason="set WIPERX_TEST_POSTGRES_URL to run against a real Postgres instance",
)
class TestPostgresBackend:
    @pytest.fixture(autouse=True)
    def _pg_db(self):
        db.init_db(os.environ["WIPERX_TEST_POSTGRES_URL"])
        yield
        # best-effort cleanup so reruns start from an empty table
        from web.db_models import MachineORM, UserORM
        with db.get_session() as session:
            session.query(UserORM).delete()
            session.query(MachineORM).delete()
            session.commit()
        db.reset_db_state_for_tests()

    def test_seed_and_login_roundtrip_on_real_postgres(self):
        seed_default_users_if_empty()
        admin = find_user_by_username("admin")
        assert admin.check_password("admin123") is True

    def test_machine_roundtrip_on_real_postgres(self):
        store = get_machine_store()
        store["pg1"] = RemoteMachine(machine_id="pg1", hostname="pg-host")
        assert get_machine_store()["pg1"].hostname == "pg-host"
