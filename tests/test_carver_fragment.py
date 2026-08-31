"""Tests for core.recovery.carver_fragment (JPEG bifragment gap carving)."""

import io
import os

import pytest

from core.recovery.carver_fragment import carve_bifragment_jpeg

pytest.importorskip("PIL")
from PIL import Image  # noqa: E402

BS = 512


def _noisy_jpeg(side: int = 160, quality: int = 88) -> bytes:
    """A JPEG with genuine entropy data (random noise, so it does not
    compress to nothing)."""
    img = Image.frombytes("RGB", (side, side), os.urandom(side * side * 3))
    buf = io.BytesIO()
    img.save(buf, "JPEG", quality=quality)
    return buf.getvalue()


def test_contiguous_recovered_byte_exact():
    jpg = _noisy_jpeg()
    res = carve_bifragment_jpeg(jpg + b"\x00" * 8000)
    assert res.validated is True
    assert res.recovered == jpg


@pytest.mark.parametrize("gap_blocks", [1, 3, 8])
def test_bifragment_recovered_byte_exact(gap_blocks):
    jpg = _noisy_jpeg()
    cut = ((len(jpg) // 2) // BS) * BS
    region = jpg[:cut] + b"\x00" * (BS * gap_blocks) + jpg[cut:] + b"\xab" * 3000

    res = carve_bifragment_jpeg(region, block_size=BS)

    assert res.validated is True
    assert res.recovered == jpg
    assert res.gap_start == cut
    assert res.frag2_start == cut + BS * gap_blocks


def test_random_gap_recovered():
    jpg = _noisy_jpeg()
    cut = ((len(jpg) // 2) // BS) * BS
    region = jpg[:cut] + os.urandom(BS * 4) + jpg[cut:] + b"\xab" * 3000
    res = carve_bifragment_jpeg(region, block_size=BS)
    assert res.recovered == jpg
    assert res.validated is True


def test_garbage_region_returns_none():
    res = carve_bifragment_jpeg(b"\x33" * 6000)
    assert res.recovered is None
    assert res.validated is False


def test_truncated_no_eoi_returns_none():
    jpg = _noisy_jpeg()
    res = carve_bifragment_jpeg(jpg[:4000])
    assert res.recovered is None
    assert res.validated is False
