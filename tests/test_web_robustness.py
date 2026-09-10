"""Regression tests for the A3 (web robustness) hardening phase.

Covers: the live-wipe worker thread always terminating the SSE stream (WEB-01),
the 409 guard against a colliding concurrent op (WEB-02), the pending-wipe
replay fix (WEB-03), and opt-in WIPERX_STATE_DIR store persistence (WEB-06).
"""

import importlib
import types

import pytest


_PENDING_WIPE = {
    "disk_id": "sdz",
    "confirmed_name": "sdz",
    "machine_id": "local",
    "operator": "ci",
    "force_unmount": False,
}

_PENDING_RECOVERY = {
    "source": "/tmp/does-not-matter.dd",
    "operator": "ci",
    "allow_mounted": False,
    "mode": "full",
}


class _FakeManager:
    """Stands in for ExecutionManager - never touches a real disk."""

    def __init__(self, *args, **kwargs):
        pass

    def execute_wipe(self, request):
        return types.SimpleNamespace(success=True, error=None)


class _FakeReporter:
    def __init__(self, *args, **kwargs):
        pass

    def generate_json_report(self, *args, **kwargs):
        return "/tmp/report.json"

    def generate_pdf_report(self, *args, **kwargs):
        return None

    def generate_signed_json_report(self, *args, **kwargs):
        return None


@pytest.fixture(autouse=True)
def _clear_queues():
    """The SSE queue dicts are module globals - isolate every test."""
    from web.blueprints.recovery import _recovery_queues
    from web.blueprints.wipe import _wipe_queues

    _wipe_queues.clear()
    _recovery_queues.clear()
    yield
    _wipe_queues.clear()
    _recovery_queues.clear()


def _arm_wipe(client):
    with client.session_transaction() as sess:
        sess["pending_wipe"] = dict(_PENDING_WIPE)


# --------------------------------------------------------------------------- #
# WEB-01 - a report-writer error still terminates the stream
# --------------------------------------------------------------------------- #


def test_thread_death_still_queues_done(admin, monkeypatch):
    monkeypatch.setattr("web.blueprints.wipe.ExecutionManager", _FakeManager)

    class _BoomReporter(_FakeReporter):
        def generate_json_report(self, *args, **kwargs):
            raise RuntimeError("disk full")

    monkeypatch.setattr("core.report_generator.ReportGenerator", _BoomReporter)

    _arm_wipe(admin)
    assert admin.post("/wipe/run").status_code == 200

    body = admin.get("/wipe/stream/1").get_data(as_text=True)
    assert '"type": "done"' in body
    assert '"success": false' in body
    assert "disk full" in body


# --------------------------------------------------------------------------- #
# WEB-02 - a second concurrent op for the same account is rejected with 409
# --------------------------------------------------------------------------- #


def test_second_wipe_run_returns_409(admin, monkeypatch):
    monkeypatch.setattr("web.blueprints.wipe.ExecutionManager", _FakeManager)
    monkeypatch.setattr("core.report_generator.ReportGenerator", _FakeReporter)

    _arm_wipe(admin)
    assert admin.post("/wipe/run").status_code == 200

    # The first stream was never consumed, so its queue is still registered.
    _arm_wipe(admin)
    resp = admin.post("/wipe/run")
    assert resp.status_code == 409
    assert resp.get_json()["error"]


def test_recovery_second_run_returns_409(admin, monkeypatch):
    def _fake_recover(*args, **kwargs):
        return {"summary": {"total": 0}, "signed": None, "manifest_sha256": "d00d"}

    monkeypatch.setattr("core.recovery.service.recover", _fake_recover)

    with admin.session_transaction() as sess:
        sess["pending_recovery"] = dict(_PENDING_RECOVERY)
    assert admin.post("/recovery/run").status_code == 200

    resp = admin.post("/recovery/run")
    assert resp.status_code == 409
    assert resp.get_json()["error"]


# --------------------------------------------------------------------------- #
# WEB-03 - pending_wipe is consumed once; a re-POST cannot replay the wipe
# --------------------------------------------------------------------------- #


def test_pending_wipe_cleared_after_run(admin, monkeypatch):
    monkeypatch.setattr("web.blueprints.wipe.ExecutionManager", _FakeManager)
    monkeypatch.setattr("core.report_generator.ReportGenerator", _FakeReporter)

    _arm_wipe(admin)
    assert admin.post("/wipe/run").status_code == 200

    with admin.session_transaction() as sess:
        assert "pending_wipe" not in sess

    # No pending params left -> the replay POST is a plain 400, not a re-wipe.
    assert admin.post("/wipe/run").status_code == 400


# --------------------------------------------------------------------------- #
# WEB-06 - WIPERX_STATE_DIR persists the machine store across a restart
# --------------------------------------------------------------------------- #


def test_state_dir_persists_machines(tmp_path, monkeypatch):
    import web.models as models

    monkeypatch.setenv("WIPERX_STATE_DIR", str(tmp_path))
    try:
        importlib.reload(models)
        models.get_machine_store()["m1"] = models.RemoteMachine(
            machine_id="m1", hostname="host.example"
        )
        assert (tmp_path / "machines.json").exists()

        # Simulate a process restart.
        importlib.reload(models)
        assert "m1" in models.get_machine_store()
    finally:
        monkeypatch.undo()
        importlib.reload(models)
