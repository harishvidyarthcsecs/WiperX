"""Tests for core.wipe_passes overwrite-pattern tables.

Claude reference test file; Codex delivers an independent set. Keep both green.
"""

import pytest

from core.wipe_passes import PassSpec, describe, methods, pass_spec


def test_pass_counts():
    assert len(pass_spec("clear")) == 2
    assert len(pass_spec("zero")) == 1
    assert len(pass_spec("random")) == 1
    assert len(pass_spec("dod")) == 3
    assert len(pass_spec("dod-3")) == 3
    assert len(pass_spec("dod-7")) == 7
    assert len(pass_spec("gutmann")) == 35
    assert len(pass_spec("nist-purge")) == 2


def test_dod_byte_values():
    specs = pass_spec("dod")
    assert specs[0] == PassSpec("fixed", 0x00)
    assert specs[1] == PassSpec("fixed", 0xFF)
    assert specs[2].kind == "random"


def test_gutmann_shape():
    specs = pass_spec("gutmann")
    assert [s.kind for s in specs[:4]] == ["random"] * 4
    assert [s.kind for s in specs[-4:]] == ["random"] * 4
    assert all(s.kind == "fixed" for s in specs[4:31])


def test_passspec_is_frozen_and_hashable():
    spec = PassSpec("fixed", 0x55)
    with pytest.raises(Exception):
        spec.byte = 1  # frozen
    assert len({spec, PassSpec("fixed", 0x55)}) == 1


def test_case_insensitive():
    assert pass_spec("DOD") == pass_spec("dod")
    assert pass_spec("  Gutmann ") == pass_spec("gutmann")


def test_unknown_method_raises():
    with pytest.raises(ValueError):
        pass_spec("shred")
    with pytest.raises(ValueError):
        describe("bogus")


def test_methods_sorted_and_complete():
    m = methods()
    assert m == sorted(m)
    for name in ("auto", "clear", "zero", "random", "dod", "dod-7", "gutmann", "nist-purge"):
        assert name in m


def test_invalid_passspec_rejected():
    with pytest.raises(ValueError):
        PassSpec("fixed", 999)
    with pytest.raises(ValueError):
        PassSpec("bogus")
    with pytest.raises(ValueError):
        PassSpec("random", 1)
