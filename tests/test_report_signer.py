"""Tests for core.report_signer (Ed25519 signed report envelopes)."""

import pytest

from core import report_signer as rs


@pytest.fixture(autouse=True)
def _isolated_key(tmp_path, monkeypatch):
    monkeypatch.setenv("WIPERX_SIGN_KEY", str(tmp_path / "k.pem"))
    monkeypatch.delenv("WIPERX_VERIFY_PUBKEY", raising=False)
    yield


def test_canonical_bytes_key_order_independent():
    a = rs.canonical_bytes({"b": 1, "a": 2, "z": {"y": 1, "x": 2}})
    b = rs.canonical_bytes({"a": 2, "z": {"x": 2, "y": 1}, "b": 1})
    assert a == b


def test_sign_then_verify_valid():
    env = rs.sign_payload({"disk": "sdb", "passes": 3})
    result = rs.verify_payload(env)
    assert result["valid"] is True
    assert result["key_id"] == env["signature"]["key_id"]


def test_tampered_payload_is_invalid():
    env = rs.sign_payload({"disk": "sdb", "ok": True})
    env["payload"]["ok"] = False
    result = rs.verify_payload(env)
    assert result["valid"] is False
    assert "alter" in result["reason"].lower()


def test_malformed_envelope():
    assert rs.verify_payload({"payload": {}})["valid"] is False
    assert rs.verify_payload({"signature": {}})["valid"] is False
    assert rs.verify_payload("nope")["valid"] is False


def test_write_and_verify_file_round_trip(tmp_path):
    path = tmp_path / "cert.json"
    rs.write_signed_json({"hello": "world", "n": 42}, path)
    result = rs.verify_file(path)
    assert result["valid"] is True


def test_verify_file_non_json(tmp_path):
    bad = tmp_path / "bad.json"
    bad.write_text("this is not json {")
    result = rs.verify_file(bad)
    assert result["valid"] is False
    assert "read" in result["reason"].lower() or "json" in result["reason"].lower()


def test_signature_from_other_key_not_trusted(tmp_path, monkeypatch):
    # Sign with key A, then point the trust anchor at a different key B.
    env = rs.sign_payload({"x": 1})
    other_key = tmp_path / "other.pem"
    monkeypatch.setenv("WIPERX_SIGN_KEY", str(other_key))
    rs.load_private_key()  # generate key B
    monkeypatch.setenv("WIPERX_VERIFY_PUBKEY", str(other_key.with_suffix(".pub.pem")))

    result = rs.verify_payload(env)
    assert result["valid"] is True
    assert result["trusted"] is False
