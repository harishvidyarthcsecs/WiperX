"""Tests for core.recovery.carver_fragment (JPEG bifragment gap carving)."""

import io
import os
import random

import pytest

from core.recovery.carver_fragment import carve_bifragment_jpeg

pytest.importorskip("PIL")
from PIL import Image  # noqa: E402

BS = 512


def _noisy_jpeg(side: int = 160, quality: int = 88, seed: int | None = None) -> bytes:
    """A JPEG with genuine entropy data (random noise, so it does not
    compress to nothing).

    `seed` picks a deterministic byte generator (random.Random.randbytes)
    instead of os.urandom, which the stdlib random module cannot seed - a
    fixed seed makes a failing case reproducible instead of a 1-in-N flake.
    Omit seed to keep the original unseeded-CSPRNG behavior.
    """
    pixels = (random.Random(seed).randbytes(side * side * 3)
              if seed is not None else os.urandom(side * side * 3))
    img = Image.frombytes("RGB", (side, side), pixels)
    buf = io.BytesIO()
    img.save(buf, "JPEG", quality=quality)
    return buf.getvalue()


def test_contiguous_recovered_byte_exact():
    jpg = _noisy_jpeg()
    res = carve_bifragment_jpeg(jpg + b"\x00" * 8000)
    assert res.validated is True
    assert res.recovered == jpg


@pytest.mark.parametrize("gap_blocks", [1, 2, 3, 4, 5, 8])
@pytest.mark.parametrize("seed", [0, 1, 2])
def test_bifragment_recovered_byte_exact(gap_blocks, seed):
    jpg = _noisy_jpeg(seed=seed)
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
