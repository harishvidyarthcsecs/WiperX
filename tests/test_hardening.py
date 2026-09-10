"""Regression tests for the A1 (security) + A2 (crash) hardening phase.

Covers: report-download path traversal, login open-redirect, CSRF enforcement,
the eraser/recovery filesystem sandbox, and the two verify_file / view() 500s.
"""

import json

import pytest

from core import report_signer
from web.blueprints import reports as reports_bp_mod


# --------------------------------------------------------------------------- #
# SEC-01 / SEC-09 - report download / view cannot escape reports|cases
# --------------------------------------------------------------------------- #


@pytest.mark.parametrize(
    "bad",
    [
        "cases/../keys/wiperx_sign_key.pem",
        "../.env",
        "../keys/wiperx_sign_key.pem",
        "cases/../../.env",
    ],
)
def test_report_download_traversal_blocked(admin, bad):
    assert admin.get(f"/reports/download/{bad}").status_code == 404


def test_report_view_traversal_blocked(admin):
    assert admin.get("/reports/view/../.env").status_code == 404


# --------------------------------------------------------------------------- #
# SEC-03 - login open redirect
# --------------------------------------------------------------------------- #


@pytest.mark.parametrize("nxt", ["https://evil.com/x", "//evil.com", "http:evil"])
def test_login_open_redirect_blocked(client, nxt):
    resp = client.post(
        f"/auth/login?next={nxt}",
        data={"username": "admin", "password": "admin123"},
        follow_redirects=False,
    )
    assert resp.status_code == 302
    assert "evil.com" not in resp.headers["Location"]


def test_login_local_next_is_kept(client):
    resp = client.post(
        "/auth/login?next=/reports/",
        data={"username": "admin", "password": "admin123"},
        follow_redirects=False,
    )
    assert resp.status_code == 302
    assert resp.headers["Location"].endswith("/reports/")


# --------------------------------------------------------------------------- #
# SEC-02 - CSRF is enforced when enabled
# --------------------------------------------------------------------------- #


def test_post_without_csrf_token_is_rejected(csrf_client):
    resp = csrf_client.post(
        "/auth/login", data={"username": "admin", "password": "admin123"}
    )
    assert resp.status_code == 400


# --------------------------------------------------------------------------- #
# SEC-04 / SEC-06 - eraser sandbox (incl. wipe_free_mount)
# --------------------------------------------------------------------------- #


def test_eraser_rejects_path_outside_root(admin):
    resp = admin.post(
        "/eraser/run",
        data={"wipe_free_mount": "/etc", "passes": "1"},
        follow_redirects=False,
    )
    assert resp.status_code == 302
    assert resp.headers["Location"].endswith("/eraser/")


def test_eraser_bad_passes_does_not_500(admin):
    resp = admin.post(
        "/eraser/run",
        data={"wipe_free_mount": "/etc", "passes": "abc"},
        follow_redirects=False,
    )
    assert resp.status_code != 500


# --------------------------------------------------------------------------- #
# CR-01 - crypto missing must not 500 the dashboard / reports
# --------------------------------------------------------------------------- #


def test_dashboard_survives_missing_crypto(admin, monkeypatch, tmp_path):
    monkeypatch.setattr(report_signer, "_CRYPTO_OK", False)
    monkeypatch.setattr(reports_bp_mod, "REPORTS_DIR", tmp_path)
    (tmp_path / "wipe_x_000000Z.json").write_text(
        json.dumps({"payload": {"operation": {}}, "signature": {"alg": "Ed25519"}})
    )
    assert admin.get("/").status_code == 200
    assert admin.get("/reports/").status_code == 200


# --------------------------------------------------------------------------- #
# CR-05 - non-JSON report file -> 404, not 500
# --------------------------------------------------------------------------- #


def test_report_view_non_json_is_404(admin, monkeypatch, tmp_path):
    monkeypatch.setattr(reports_bp_mod, "REPORTS_DIR", tmp_path)
    (tmp_path / "wipe_bad_000000Z.json").write_text("this is not json {{{")
    assert admin.get("/reports/view/wipe_bad_000000Z.json").status_code == 404
