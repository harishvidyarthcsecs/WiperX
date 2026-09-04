"""
Regression tests for the fixes made during the pendrive analysis pass.

Covers findings: 1 (verifier read-error tolerance), 2 (fresh random per chunk),
3 (partition wipe target), 6 (swallowed verification failure), 17 (verify-report
exit code honours trust anchor), plus report_generator import-time purity.
"""

from __future__ import annotations

import os
import subprocess
import sys
from pathlib import Path

REPO = Path(__file__).resolve().parent.parent
from core.os_detector import OSType  # noqa: E402


class _FakeExecutor:
    def __init__(self, per_offset):
        self.per_offset = per_offset

    def run_command(self, cmd, timeout=None):
        return self.per_offset(cmd)


def _od_zeros(n=4096):
    return " ".join(["00"] * n)


def test_verifier_passes_with_read_errors_under_tolerance(monkeypatch):
    from core import verifier as vmod
    from core.verifier import WipeVerifier

    class _NotLocal:
        pass

    monkeypatch.setattr(vmod, "LocalExecutor", _NotLocal, raising=False)
    calls = {"n": 0}

    def per_offset(cmd):
        calls["n"] += 1
        if calls["n"] % 20 == 0:
            raise OSError("transient USB read error")
        return _od_zeros()

    disk = type("D", (), {"identifier": "disk9", "size_bytes": 8_000_000_000})()
    res = WipeVerifier().verify(disk, _FakeExecutor(per_offset), OSType.MACOS,
                                expected="zeroed", sample_count=200)
    assert res["read_errors"] > 0
    assert res["verified"] is True
    assert 0 < res["read_error_ratio"] <= WipeVerifier.READ_ERROR_TOLERANCE


def test_verifier_inconclusive_when_read_errors_over_tolerance(monkeypatch):
    from core import verifier as vmod
    from core.verifier import WipeVerifier

    class _NotLocal:
        pass

    monkeypatch.setattr(vmod, "LocalExecutor", _NotLocal, raising=False)

    def per_offset(cmd):
        raise OSError("device not ready")

    disk = type("D", (), {"identifier": "disk9", "size_bytes": 8_000_000_000})()
    res = WipeVerifier().verify(disk, _FakeExecutor(per_offset), OSType.MACOS,
                                expected="zeroed", sample_count=50)
    assert res["verified"] is None


def test_verifier_fails_hard_on_live_data(monkeypatch):
    from core import verifier as vmod
    from core.verifier import WipeVerifier

    class _NotLocal:
        pass

    monkeypatch.setattr(vmod, "LocalExecutor", _NotLocal, raising=False)

    def per_offset(cmd):
        return " ".join(f"{b:02x}" for b in os.urandom(4096))

    disk = type("D", (), {"identifier": "disk9", "size_bytes": 8_000_000_000})()
    res = WipeVerifier().verify(disk, _FakeExecutor(per_offset), OSType.MACOS,
                                expected="zeroed", sample_count=40)
    assert res["verified"] is False


def test_shredder_uses_fresh_random_per_chunk(tmp_path, monkeypatch):
    from core.eraser_file import file_shredder

    p = tmp_path / "big.bin"
    p.write_bytes(b"A" * (3 * 1024 * 1024))

    calls = {"n": 0}
    real_urandom = os.urandom

    def counting_urandom(n):
        calls["n"] += 1
        return real_urandom(n)

    monkeypatch.setattr(file_shredder.os, "urandom", counting_urandom)
    res = file_shredder.shred_file(str(p), passes=1, zero_final=False, rename_rounds=0)
    assert res.ok is True
    assert calls["n"] >= 3


def test_macos_strategy_unmounts_slice_for_partition():
    from core.disk_scanner import DiskInfo
    from core.strategies import MacOSWipeStrategy

    cmds = []

    class Ex:
        def run_command(self, cmd, timeout=None):
            cmds.append(cmd)
            return ""

    part = DiskInfo(identifier="disk8s1", size_bytes=8_000_000_000, bus_type="USB",
                    disk_type="HDD", is_system=False, is_mounted=True,
                    is_partition=True, parent_identifier="disk8")
    MacOSWipeStrategy().execute(part, Ex(), passes=None)
    assert "diskutil unmount force /dev/disk8s1" in cmds
    assert not any("unmountDisk" in c for c in cmds)
    assert "diskutil secureErase 0 disk8s1" in cmds


def test_macos_strategy_unmounts_whole_disk_for_disk():
    from core.disk_scanner import DiskInfo
    from core.strategies import MacOSWipeStrategy

    cmds = []

    class Ex:
        def run_command(self, cmd, timeout=None):
            cmds.append(cmd)
            return ""

    whole = DiskInfo(identifier="disk8", size_bytes=8_000_000_000, bus_type="USB",
                     disk_type="HDD", is_system=False, is_mounted=True)
    MacOSWipeStrategy().execute(whole, Ex(), passes=None)
    assert "diskutil unmountDisk force /dev/disk8" in cmds


def test_execute_wipe_marks_failure_when_verification_fails(monkeypatch):
    from core import execution_manager as em
    import core.verifier as vmod

    mgr = em.ExecutionManager()
    disk = type("D", (), {
        "identifier": "disk8", "model": "USB", "serial": "", "size_human": "8 GB",
        "size_bytes": 8_000_000_000, "disk_type": "HDD", "bus_type": "USB",
        "is_system": False, "is_mounted": False, "partitions": [],
    })()

    class FakeExec:
        def close(self):
            pass

    monkeypatch.setattr(mgr, "_build_executor_and_detect_os",
                        lambda *a, **k: (FakeExec(), OSType.MACOS))
    monkeypatch.setattr(mgr, "_check_privileges", lambda *a, **k: None)

    class FakeScanner:
        def __init__(self, *a, **k):
            pass

        def scan(self):
            return [disk]

    monkeypatch.setattr(em, "DiskScanner", FakeScanner)

    class FakeStrategy:
        name = "fake"
        description = "fake"

        def execute(self, **k):
            return True

    monkeypatch.setattr(em, "get_strategy", lambda **k: FakeStrategy())
    monkeypatch.setattr(
        vmod.WipeVerifier, "verify",
        lambda self, *a, **k: {"verified": False, "method": "entropy_sampling",
                               "details": "3 samples look live"},
    )

    req = em.WipeRequest(disk_identifier="disk8", confirmed_disk_name="disk8")
    result = mgr.execute_wipe(req)
    assert result.success is False
    assert "verification" in (result.error or "").lower()


def _run_cli(args, env):
    return subprocess.run([sys.executable, "-m", "cli.wiperx_cli", *args],
                          cwd=REPO, env=env, capture_output=True, text=True)


def test_verify_report_exit_code_honours_trust_anchor(tmp_path):
    from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
    from cryptography.hazmat.primitives import serialization as ser
    from core import report_signer

    signkey = tmp_path / "sign.pem"
    saved = os.environ.copy()
    os.environ["WIPERX_SIGN_KEY"] = str(signkey)
    os.environ.pop("WIPERX_VERIFY_PUBKEY", None)
    try:
        cert = tmp_path / "cert.json"
        report_signer.write_signed_json({"hello": "world"}, cert)
    finally:
        os.environ.clear()
        os.environ.update(saved)

    env = dict(os.environ)
    env["WIPERX_SIGN_KEY"] = str(signkey)
    env.pop("WIPERX_VERIFY_PUBKEY", None)

    r = _run_cli(["verify-report", str(cert)], env)
    assert r.returncode == 0, r.stdout + r.stderr

    other_pub = tmp_path / "other.pub.pem"
    other_pub.write_bytes(
        Ed25519PrivateKey.generate().public_key().public_bytes(
            ser.Encoding.PEM, ser.PublicFormat.SubjectPublicKeyInfo)
    )
    env2 = dict(env)
    env2["WIPERX_VERIFY_PUBKEY"] = str(other_pub)
    assert _run_cli(["verify-report", str(cert)], env2).returncode == 1
    assert _run_cli(["verify-report", "--allow-untrusted", str(cert)], env2).returncode == 0


def test_report_generator_import_has_no_side_effect():
    code = (
        "import sys; sys.path.insert(0, %r); "
        "import core.report_generator as rg; print('OK')" % str(REPO)
    )
    out = subprocess.run([sys.executable, "-c", code], capture_output=True, text=True)
    assert out.returncode == 0, out.stderr
    assert "OK" in out.stdout
