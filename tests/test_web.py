"""Smoke + RBAC tests for the WiperX Flask blueprints (incl. recovery)."""


def test_anonymous_is_redirected_to_login(client):
    resp = client.get("/")
    assert resp.status_code == 302
    assert "/auth/login" in resp.headers["Location"]


def test_admin_can_load_core_pages(admin):
    for path in ("/", "/recovery/", "/recovery/cases/", "/eraser/", "/reports/"):
        resp = admin.get(path)
        assert resp.status_code == 200, (path, resp.status_code)


def test_admin_reports_page_parses_real_certs(admin):
    """Regression: the legacy signed wipe certs on disk must not show as
    Unknown/FAILED — reports.index must unwrap the {payload,signature} envelope."""
    body = admin.get("/reports/").get_data(as_text=True)
    assert "Unknown</td>" not in body


def test_admin_dashboard_shows_action_cards(admin):
    body = admin.get("/").get_data(as_text=True)
    assert "Erase Drive" in body
    assert "Erase Files" in body
    assert "Recover" in body


def test_admin_can_view_audit_log(admin):
    resp = admin.get("/audit")
    assert resp.status_code == 200
    assert "AUDIT LOG" in resp.get_data(as_text=True)


def test_viewer_cannot_reach_recovery(viewer):
    resp = viewer.get("/recovery/", follow_redirects=False)
    assert resp.status_code == 302


def test_viewer_recovery_run_is_forbidden(viewer):
    resp = viewer.post("/recovery/run")
    assert resp.status_code == 403


def test_viewer_cannot_view_audit_log(viewer):
    resp = viewer.get("/audit", follow_redirects=False)
    assert resp.status_code == 302


def test_recovery_run_without_pending_returns_400(admin):
    resp = admin.post("/recovery/run")
    assert resp.status_code == 400


def test_recovery_case_404_for_unknown(admin):
    assert admin.get("/recovery/case/does-not-exist").status_code == 404
