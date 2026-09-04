"""Tests for the reports loader (envelope unwrap) and report_paths naming."""

from datetime import datetime

from core.report_paths import kind_of, report_path, slug
from core.report_signer import write_signed_json
from web.blueprints.reports import _summarize, _unwrap


def test_slug_rules():
    assert slug("Harish's MacBook Pro!!") == "harish-s-macbook-pro"
    assert slug("") == "x"
    assert slug("a" * 80, max_len=10) == "aaaaaaaaaa"


def test_report_path_shape(tmp_path):
    when = datetime(2026, 9, 1, 13, 15, 0)
    p = report_path("wipe", "disk8", when=when, base_dir=tmp_path)
    assert p == tmp_path / "2026-09-01" / "wipe_disk8_131500Z.json"
    assert p.parent.is_dir()


def test_unwrap_envelope_and_bare():
    assert _unwrap({"payload": {"a": 1}, "signature": {"sig": "x"}}) == {"a": 1}
    assert _unwrap({"a": 1}) == {"a": 1}


def test_kind_of_new_and_legacy_names():
    assert kind_of("wipe_disk8_131500Z.json") == "wipe"
    assert kind_of("wipe_cert_sdb_2026-08-31T10-00-00Z.json") == "wipe"
    assert kind_of("erase_cert_20260831T094744Z.json") == "erase"
    assert kind_of("freespace_20260901T131500Z.json") == "freespace"
    assert kind_of("case_report.json") == "recover"
    assert kind_of("mystery.json") == "other"


def _wipe_payload(*, success=True):
    return {
        "operation": {"timestamp": "2026-08-31T10:00:00Z", "success": success, "error": None},
        "target": {"hostname": "host-x", "os_detected": "MACOS",
                   "disk_identifier": "disk8", "disk_model": "T7", "disk_serial": ""},
        "wipe": {"strategy_used": "macOS-diskutil", "method": "auto",
                 "pass_count": 0, "log_lines": []},
        "verification": {"verified": True, "method": "entropy_sampling", "details": "ok"},
    }


def _erase_payload(*, succeeded=3, failed=0):
    return {
        "wiperx_erase_report": {"schema_version": "1.0",
                                "generated_at": "2026-09-01T13:15:00Z",
                                "operator": "tester", "host": "host-x"},
        "options": {}, "summary": {"total": succeeded + failed,
                                   "succeeded": succeeded, "failed": failed},
        "files": [], "free_space_wipe": None, "fstrim": None,
    }


def test_summarize_wipe_cert_parses_real_fields(tmp_path):
    """The exact bug: an enveloped wipe cert must NOT come out as Unknown/FAILED."""
    path = tmp_path / "wipe_disk8_131500Z.json"
    write_signed_json(_wipe_payload(), path)

    row = _summarize(path)

    assert row["kind"] == "wipe"
    assert row["host"] == "host-x"
    assert row["target"] == "disk8"
    assert row["detail"] == "macOS-diskutil"
    assert row["ok"] is True
    assert row["timestamp"] != "Unknown"


def test_summarize_wipe_cert_failed_run_shows_failed(tmp_path):
    path = tmp_path / "wipe_disk8_131600Z.json"
    write_signed_json(_wipe_payload(success=False), path)
    row = _summarize(path)
    assert row["ok"] is False


def test_summarize_erase_cert(tmp_path):
    path = tmp_path / "erase_3files_131500Z.json"
    write_signed_json(_erase_payload(), path)

    row = _summarize(path)

    assert row["kind"] == "erase"
    assert row["host"] == "host-x"
    assert row["detail"] == "3/3 erased"
    assert row["ok"] is True


def test_summarize_erase_cert_with_failures(tmp_path):
    path = tmp_path / "erase_3files_131700Z.json"
    write_signed_json(_erase_payload(succeeded=2, failed=1), path)
    row = _summarize(path)
    assert row["ok"] is False
