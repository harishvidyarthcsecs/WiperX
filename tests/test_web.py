"""Smoke + RBAC tests for the WiperX Flask blueprints (incl. recovery)."""

import shutil
import subprocess

import pytest

_HAVE_EXT4_TOOLS = shutil.which("mkfs.ext4") and shutil.which("debugfs")


def test_anonymous_is_redirected_to_login(client):
    resp = client.get("/")
    assert resp.status_code == 302
    assert "/auth/login" in resp.headers["Location"]


def test_admin_can_load_core_pages(admin):
    for path in ("/", "/recovery/", "/recovery/cases/", "/eraser/", "/reports/"):
        resp = admin.get(path)
        assert resp.status_code == 200, (path, resp.status_code)


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


@pytest.mark.skipif(not _HAVE_EXT4_TOOLS, reason="mkfs.ext4/debugfs not installed")
def test_recovery_case_view_renders_fs_recovered_record(tmp_path, admin, monkeypatch):
    """
    Regression test: a case containing a filesystem-undelete record (method
    "fs", no "offset" field - only carve records have one) must render
    without a 500. Previously recovery/case.html did
    "%#x"|format(f.offset) unconditionally, which crashed with
    "TypeError: %x format: an integer is required, not Undefined" on any
    fs-recovered file, i.e. the common case for a real deleted-file
    recovery, not just carved payloads.
    """
    import web.blueprints.recovery as rec_bp
    import web.blueprints.dashboard as dash_bp
    from core.recovery import service

    cases_root = tmp_path / "cases"
    monkeypatch.setattr(rec_bp, "CASES_DIR", cases_root)
    monkeypatch.setattr(dash_bp, "CASES_DIR", cases_root)

    seed = tmp_path / "seed"
    seed.mkdir()
    (seed / "deleted_me.txt").write_bytes(b"fs-recovery regression fixture\n")

    image = tmp_path / "fs_image.img"
    subprocess.run(
        ["dd", "if=/dev/zero", f"of={image}", "bs=1M", "count=16", "status=none"],
        check=True,
    )
    subprocess.run(["mkfs.ext4", "-q", "-F", "-d", str(seed), str(image)], check=True)
    rm = subprocess.run(
        ["debugfs", "-w", "-R", "rm /deleted_me.txt", str(image)],
        capture_output=True, text=True,
    )
    assert rm.returncode == 0, rm.stderr

    name = "web-fs-testcase"
    res = service.recover(
        str(image), str(cases_root / name), operator="pytest", fs_only=True,
    )
    assert res["signed"] is True
    assert res["summary"]["total"] >= 1
    assert res["summary"]["by_method"].get("fs", 0) >= 1

    page = admin.get(f"/recovery/case/{name}")
    assert page.status_code == 200
    body = page.get_data(as_text=True)
    assert "deleted_me.txt" in body
    assert "filesystem:" in body
