"""Tests for core.recovery.signatures (magic-number table + scanner)."""

from core.recovery.signatures import (
    MAX_HEADER_LEN,
    SIGNATURES,
    by_name,
    iter_header_hits,
    match_at,
)

_PNG = b"\x89PNG\r\n\x1a\n"
_JPEG = b"\xff\xd8\xff\xe0"
_ZIP = b"PK\x03\x04"
_MP4 = b"\x00\x00\x00\x18ftypmp42"  # 'ftyp' at offset 4


def test_match_at_offset_zero():
    assert match_at(_PNG + b"\x00" * 16, 0).name == "png"
    assert match_at(_JPEG + b"junk", 0).name == "jpeg"
    assert match_at(_ZIP + b"junk", 0).name == "zip"
    assert match_at(b"nothing here", 0) is None


def test_match_at_respects_header_at():
    assert match_at(_MP4 + b"\x00" * 32, 0).name == "mp4"
    assert match_at(b"ftyp" + b"\x00" * 32, 0) is None  # not at header_at


def test_iter_header_hits_finds_every_planted_header():
    blob = bytearray(b"\x00" * 4096)
    for off, magic in ((512, _PNG), (2048, _JPEG), (3072, _ZIP)):
        blob[off:off + len(magic)] = magic
    hits = list(iter_header_hits(bytes(blob), base_offset=0))
    found = {(off, sig.name) for off, sig in hits}
    assert (512, "png") in found
    assert (2048, "jpeg") in found
    assert (3072, "zip") in found


def test_iter_header_hits_absolute_offset():
    buf = b"\x00" * 100 + _PNG + b"\x00" * 100
    hits = list(iter_header_hits(buf, base_offset=10_000))
    assert hits and hits[0][0] == 10_100


def test_by_name_and_aliases():
    assert by_name("jpeg").ext == "jpg"
    assert by_name("docx").name == "zip"      # OOXML alias -> zip signature
    assert by_name("xlsx").name == "zip"
    assert by_name("totally-unknown") is None


def test_max_header_len_covers_longest_header():
    longest = max(sig.header_at + len(h) for sig in SIGNATURES for h in sig.headers)
    assert MAX_HEADER_LEN >= longest
