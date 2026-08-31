"""Tests for core.entropy (Shannon entropy + wiped-sample classifier).

Claude reference test file; Codex delivers an independent set.
"""

import os

from core.entropy import looks_wiped, shannon


def test_shannon_bounds():
    assert shannon(b"") == 0.0
    assert shannon(b"\x00" * 4096) == 0.0
    assert shannon(b"A" * 1000) == 0.0
    assert shannon(bytes(range(256)) * 16) > 7.9


def test_looks_wiped_zeroed():
    v = looks_wiped(b"\x00" * 4096)
    assert v.verdict == "zeroed"
    assert v.dominant_byte == 0
    assert v.fill_ratio == 1.0


def test_looks_wiped_fixed_fill():
    v = looks_wiped(b"\xff" * 4096)
    assert v.verdict == "fixed-fill"
    assert v.dominant_byte == 0xFF


def test_looks_wiped_random():
    v = looks_wiped(os.urandom(4096))
    assert v.verdict == "random-or-live"
    assert v.entropy > 7.0


def test_looks_wiped_low_entropy():
    buf = b"\x00" * 3800 + os.urandom(296)
    assert looks_wiped(buf).verdict in ("low-entropy", "zeroed")


def test_empty_buffer_is_zeroed():
    v = looks_wiped(b"")
    assert v.verdict == "zeroed"
    assert v.dominant_byte is None
