"""Shared pytest fixtures for the WiperX web layer."""

import os

# Pin the demo credentials before web.models builds its user store at import.
os.environ.setdefault("WIPERX_ADMIN_PASSWORD", "admin123")
os.environ.setdefault("WIPERX_OPERATOR_PASSWORD", "operator123")
os.environ.setdefault("WIPERX_VIEWER_PASSWORD", "viewer123")

import pytest

from web.app import create_app


@pytest.fixture
def app(tmp_path_factory):
    # A real, isolated sandbox root so the fail-closed eraser/recovery checks
    # (web/blueprints/_fsroot.py) are deterministic in tests.
    sandbox = tmp_path_factory.mktemp("fsroot")
    application = create_app({
        "TESTING": True,
        "SECRET_KEY": "test-secret",
        "WTF_CSRF_ENABLED": False,
        "ERASE_ALLOWED_ROOT": str(sandbox),
        "RECOVER_ALLOWED_ROOT": str(sandbox),
    })
    application.config["FSROOT_SANDBOX"] = str(sandbox)
    return application


@pytest.fixture
def client(app):
    return app.test_client()


@pytest.fixture
def csrf_client(tmp_path_factory):
    """A client with CSRF protection left ON (for negative tests)."""
    sandbox = tmp_path_factory.mktemp("fsroot_csrf")
    application = create_app({
        "TESTING": True,
        "SECRET_KEY": "test-secret",
        "WTF_CSRF_ENABLED": True,
        "ERASE_ALLOWED_ROOT": str(sandbox),
        "RECOVER_ALLOWED_ROOT": str(sandbox),
    })
    return application.test_client()


def _login(client, username, password):
    return client.post(
        "/auth/login",
        data={"username": username, "password": password},
        follow_redirects=True,
    )


@pytest.fixture
def admin(client):
    _login(client, "admin", "admin123")
    return client


@pytest.fixture
def viewer(client):
    _login(client, "viewer", "viewer123")
    return client
