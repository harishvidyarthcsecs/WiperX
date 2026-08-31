"""End-to-end tests for Module 3 (carving & recovery).

Builds a synthetic image with known PNG / JPEG / PDF / ZIP payloads at
known offsets, carves it, and checks byte-exact recovery + a signed,
deterministic case report.
"""

import hashlib
import io
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


def test_open_source_rejects_missing(tmp_path):
    with pytest.raises(SourceError):
        open_source(str(tmp_path / "nope.img"))


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


def test_png_validates_intact(tmp_path):
    img, _placed, assets = _build_image(tmp_path)
    res = service.recover(str(img), str(tmp_path / "c"), operator="x", carve_only=True)
    png_hash = hashlib.sha256(assets["png"]).hexdigest()
    png_rec = next(r for r in res["records"] if r["sha256"] == png_hash)
    assert png_rec["validation_state"] == "intact"
    assert png_rec["confidence_band"] == "high"
