"""End-to-end tests for Module 3 (carving & recovery).

Builds a synthetic image with known PNG / JPEG / PDF / ZIP payloads at
known offsets, carves it, and checks byte-exact recovery + a signed,
deterministic case report.
"""

import hashlib
import io
import os
import zipfile

import pytest

from core.recovery import service
from core.recovery.acquire import SourceError, open_source

pytest.importorskip("PIL")
from PIL import Image  # noqa: E402


def _png_bytes(color) -> bytes:
    buf = io.BytesIO()
    Image.new("RGB", (16, 16), color).save(buf, format="PNG")
    return buf.getvalue()


def _jpeg_bytes(color) -> bytes:
    buf = io.BytesIO()
    Image.new("RGB", (32, 32), color).save(buf, format="JPEG", quality=90)
    return buf.getvalue()


def _zip_bytes() -> bytes:
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w", zipfile.ZIP_DEFLATED) as zf:
        zf.writestr("notes.txt", "recovered zip payload " * 20)
    return buf.getvalue()


def _pdf_bytes() -> bytes:
    pypdf = pytest.importorskip("pypdf")
    writer = pypdf.PdfWriter()
    writer.add_blank_page(width=200, height=200)
    buf = io.BytesIO()
    writer.write(buf)
    return buf.getvalue()


def _build_image(tmp_path):
    assets = {
        "png": _png_bytes((200, 30, 30)),
        "jpeg": _jpeg_bytes((30, 120, 200)),
        "zip": _zip_bytes(),
        "pdf": _pdf_bytes(),
    }
    blob = bytearray(b"\x00" * (256 * 1024))
    placed = {}
    for name, data in assets.items():
        while len(blob) % 4096:
            blob.append(0)
        placed[name] = (len(blob), data)
        blob.extend(data)
        blob.extend(b"\x00" * 8192)  # gap
    img = tmp_path / "disk.img"
    img.write_bytes(blob)
    return img, placed, assets


def _noisy_jpeg(side=160, quality=88):
    img = Image.frombytes("RGB", (side, side), os.urandom(side * side * 3))
    buf = io.BytesIO()
    img.save(buf, "JPEG", quality=quality)
    return buf.getvalue()


def test_open_source_rejects_missing(tmp_path):
    with pytest.raises(SourceError):
        open_source(str(tmp_path / "nope.img"))


def test_fragmented_jpeg_is_reassembled(tmp_path):
    jpg = _noisy_jpeg()
    bs = 512
    cut = ((len(jpg) // 2) // bs) * bs

    blob = bytearray(b"\x00" * (128 * 1024))
    start = len(blob)
    blob.extend(jpg[:cut])
    blob.extend(b"\x00" * (bs * 4))          # fragmentation gap
    blob.extend(jpg[cut:])
    blob.extend(b"\x00" * 8192)
    img = tmp_path / "frag.img"
    img.write_bytes(blob)

    res = service.recover(str(img), str(tmp_path / "casef"),
                          operator="pytest", carve_only=True)

    rec = next((r for r in res["records"] if r.get("carve_method") == "bifragment"), None)
    assert rec is not None, res["records"]
    assert rec["sha256"] == hashlib.sha256(jpg).hexdigest()
    assert rec["offset"] == start
    assert rec["confidence_band"] in ("high", "medium")


def test_carve_recovers_known_payloads(tmp_path):
    img, _placed, assets = _build_image(tmp_path)
    out = tmp_path / "case1"

    res = service.recover(str(img), str(out), operator="pytest", carve_only=True)

    assert res["summary"]["total"] >= 3
    assert res["signed"] is True
    assert (out / "case_report.json").exists()

    carved_hashes = {r["sha256"] for r in res["records"]}
    assert hashlib.sha256(assets["png"]).hexdigest() in carved_hashes
    assert hashlib.sha256(assets["jpeg"]).hexdigest() in carved_hashes

    for r in res["records"]:
        assert r["category"]
        assert r["validation_state"] in ("intact", "partial", "corrupt", "unchecked")
        assert 0.0 <= r["confidence_score"] <= 1.0
        assert r["confidence_band"] in ("high", "medium", "low")


def test_case_report_is_signed_and_verifies(tmp_path):
    img, _placed, _assets = _build_image(tmp_path)
    out = tmp_path / "case2"
    res = service.recover(str(img), str(out), operator="pytest", carve_only=True)

    from core.report_signer import verify_file

    v = verify_file(res["report_path"])
    assert v["valid"] is True


def test_manifest_hash_is_deterministic(tmp_path):
    img, _placed, _assets = _build_image(tmp_path)
    a = service.recover(str(img), str(tmp_path / "a"), operator="x", carve_only=True)
    b = service.recover(str(img), str(tmp_path / "b"), operator="y", carve_only=True)
    assert a["manifest_sha256"] == b["manifest_sha256"]


def test_random_filler_yields_no_false_positives(tmp_path):
    """Random data around real JPEGs must carve to exactly those JPEGs — the
    old 2-byte 'BM'/MPEG-sync signatures produced dozens of bogus carves and a
    footerless 'mp3' that swallowed the whole image."""
    jpegs = [_jpeg_bytes((i * 40, 90, 200 - i * 30)) for i in range(3)]
    blob = os.urandom(300_000)
    for j in jpegs:
        blob += j + os.urandom(120_000)
    img = tmp_path / "noise.img"
    img.write_bytes(blob)

    res = service.recover(str(img), str(tmp_path / "noisecase"),
                          operator="pytest", carve_only=True)

    recovered = {r["sha256"] for r in res["records"]}
    expected = {hashlib.sha256(j).hexdigest() for j in jpegs}
    assert recovered == expected, res["records"]


def test_junk_filters_skip_filler_and_bad_guard_magic(tmp_path):
    """Coincidental gzip/mp3 magic bytes should never survive to a full
    carve: a bad ID3/gzip guard field rejects it before the 48 MB probe is
    even read, and a homogeneous zero-filled body (entropy filter) rejects
    it even when the guard field happens to look valid.

    Each case gets its own small image with nothing after the magic bytes:
    a footerless probe reads to the end of the source, so real content
    placed downstream in the same image would leak non-filler samples into
    the entropy check and mask the very thing being tested (which real
    unallocated/wiped disk regions don't do - see
    test_random_filler_yields_no_false_positives for a real-file-amid-noise
    check of the surrounding scan logic)."""
    cases = {
        "gzip_bad_guard": b"\x1f\x8b\x08" + bytes([0xE0]) + b"\x00" * 4000,
        "gzip_filler_body": b"\x1f\x8b\x08" + bytes([0x00]) + b"\x00" * 4000,
        "mp3_bad_guard": b"ID3" + bytes([3, 0, 0x01, 0, 0, 0, 0]) + b"\x00" * 4000,
        "mp3_filler_body": b"ID3" + bytes([3, 0, 0x00, 0, 0, 0, 0]) + b"\x00" * 4000,
    }
    for name, magic_and_body in cases.items():
        blob = b"\x00" * 4096 + magic_and_body
        img = tmp_path / f"{name}.img"
        img.write_bytes(blob)

        res = service.recover(str(img), str(tmp_path / f"{name}case"),
                              operator="pytest", carve_only=True)

        sig_names = {r["signature"] for r in res["records"]}
        assert "gzip" not in sig_names and "mp3" not in sig_names, (name, res["records"])


def test_genuine_footerless_file_still_carved(tmp_path):
    """A signature with no footer/structural refiner (sqlite) and
    non-filler body content must still be carved to its size cap - the
    junk filters must never discard real footerless recoveries."""
    body = os.urandom(4000)  # non-filler content: must pass the entropy check
    sqlite_bytes = b"SQLite format 3\x00" + body
    blob = bytearray(b"\x00" * 4096)
    blob += sqlite_bytes
    blob += b"\x00" * 4096

    img = tmp_path / "sqlite.img"
    img.write_bytes(bytes(blob))

    res = service.recover(str(img), str(tmp_path / "sqlitecase"),
                          operator="pytest", carve_only=True)

    rec = next((r for r in res["records"] if r["signature"] == "sqlite"), None)
    assert rec is not None, res["records"]
    assert rec["carve_method"] == "max-size"


def test_png_validates_intact(tmp_path):
    img, _placed, assets = _build_image(tmp_path)
    res = service.recover(str(img), str(tmp_path / "c"), operator="x", carve_only=True)
    png_hash = hashlib.sha256(assets["png"]).hexdigest()
    png_rec = next(r for r in res["records"] if r["sha256"] == png_hash)
    assert png_rec["validation_state"] == "intact"
    assert png_rec["confidence_band"] == "high"


def test_recovery_case_view_via_web(tmp_path, admin, monkeypatch):
    """A signed case is browsable + verified through the recovery blueprint."""
    import web.blueprints.recovery as rec_bp
    import web.blueprints.dashboard as dash_bp

    cases_root = tmp_path / "cases"
    monkeypatch.setattr(rec_bp, "CASES_DIR", cases_root)
    monkeypatch.setattr(dash_bp, "CASES_DIR", cases_root)

    img, _placed, _assets = _build_image(tmp_path)
    name = "web-testcase"
    res = service.recover(str(img), str(cases_root / name), operator="pytest", carve_only=True)
    assert res["signed"] is True

    page = admin.get("/recovery/case/{}".format(name))
    assert page.status_code == 200
    body = page.get_data(as_text=True)
    assert "signature verified" in body
    assert ".png" in body

    listing = admin.get("/recovery/cases/")
    assert listing.status_code == 200
    assert name in listing.get_data(as_text=True)
