"""Tests for core.recovery.carver_structure.refine_end."""

import io
import zipfile

import pytest

from core.recovery.carver_structure import refine_end

pytest.importorskip("PIL")
from PIL import Image  # noqa: E402

TRAIL = b"\x00" * 4096


def _png() -> bytes:
    buf = io.BytesIO()
    Image.new("RGB", (24, 24), (10, 20, 30)).save(buf, "PNG")
    return buf.getvalue()


def _gif() -> bytes:
    buf = io.BytesIO()
    Image.new("P", (24, 24)).save(buf, "GIF")
    return buf.getvalue()


def _bmp() -> bytes:
    buf = io.BytesIO()
    Image.new("RGB", (24, 24), (200, 100, 50)).save(buf, "BMP")
    return buf.getvalue()


def _jpeg() -> bytes:
    buf = io.BytesIO()
    Image.new("RGB", (32, 32), (5, 90, 160)).save(buf, "JPEG", quality=85)
    return buf.getvalue()


def _zip() -> bytes:
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w") as zf:
        zf.writestr("a.txt", "structure test payload " * 10)
    return buf.getvalue()


def test_refine_end_trims_trailing_bytes():
    for key, data in (
        ("png", _png()),
        ("gif", _gif()),
        ("bmp", _bmp()),
        ("jpeg", _jpeg()),
        ("zip", _zip()),
    ):
        assert refine_end(data + TRAIL, key) == len(data), key


def test_refine_end_bad_input_returns_none():
    assert refine_end(b"not a png at all", "png") is None
    assert refine_end(b"\x00" * 200, "jpeg") is None
    assert refine_end(b"PK\x03\x04truncated", "zip") is None


def test_refine_end_unknown_structure_returns_none():
    assert refine_end(_png() + TRAIL, "unknown-key") is None
    assert refine_end(_png() + TRAIL, None) is None
