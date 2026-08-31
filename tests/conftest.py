"""Shared pytest fixtures for the WiperX web layer."""

import pytest

from web.app import create_app


@pytest.fixture
def app():
    application = create_app({
        "TESTING": True,
        "SECRET_KEY": "test-secret",
        "WTF_CSRF_ENABLED": False,
    })
    return application


@pytest.fixture
def client(app):
    return app.test_client()


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
