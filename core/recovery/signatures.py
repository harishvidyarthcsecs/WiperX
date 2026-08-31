# wiperx/core/recovery/signatures.py
"""
File Signature Table
--------------------
Magic-number definitions for signature-based carving. Pure data + lookup:
given a byte buffer, report which known file type (if any) starts at a
given position.

NOTE: Claude reference implementation. Codex builds an independent version;
keep whichever passes tests/test_recovery.py cleanly.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Iterator, List, Optional, Tuple


@dataclass(frozen=True)
class Signature:
    """
    One carvable file type.

    Args:
        name       : short type name ("jpeg", "png", ...).
        ext        : file extension without dot.
        category   : image | document | archive | video | audio | database | other.
        headers    : one or more magic byte strings that start the file.
        footer     : trailing magic that ends the file, or None (size-bounded).
        footer_tail: extra bytes to keep after the footer match (e.g. ZIP EOCD).
        header_at  : byte offset within the file where `headers` appears
                     (0 for most; 4 for MP4 'ftyp').
        min_bytes  : reject a carve shorter than this.
        max_bytes  : cap a footerless / runaway carve at this length.
        structure  : name of the carver_structure refiner to prefer, if any.
    """

    name: str
    ext: str
    category: str
    headers: Tuple[bytes, ...]
    footer: Optional[bytes] = None
    footer_tail: int = 0
    header_at: int = 0
    min_bytes: int = 32
    max_bytes: int = 64 * 1024 * 1024
    structure: Optional[str] = None
    aliases: Tuple[str, ...] = field(default_factory=tuple)


SIGNATURES: List[Signature] = [
    Signature("jpeg", "jpg", "image",
              headers=(b"\xff\xd8\xff\xe0", b"\xff\xd8\xff\xe1", b"\xff\xd8\xff\xdb",
                       b"\xff\xd8\xff\xee"),
              footer=b"\xff\xd9", min_bytes=128, max_bytes=32 * 1024 * 1024,
              structure="jpeg"),
    Signature("png", "png", "image",
              headers=(b"\x89PNG\r\n\x1a\n",),
              footer=b"IEND\xaeB`\x82", footer_tail=0, min_bytes=64,
              max_bytes=64 * 1024 * 1024, structure="png"),
    Signature("gif", "gif", "image",
              headers=(b"GIF87a", b"GIF89a"), footer=b"\x00\x3b",
              min_bytes=64, max_bytes=16 * 1024 * 1024),
    Signature("bmp", "bmp", "image", headers=(b"BM",),
              min_bytes=64, max_bytes=32 * 1024 * 1024, structure="bmp"),
    Signature("tiff", "tif", "image", headers=(b"II*\x00", b"MM\x00*"),
              min_bytes=64, max_bytes=64 * 1024 * 1024),
    Signature("pdf", "pdf", "document", headers=(b"%PDF-",),
              footer=b"%%EOF", footer_tail=6, min_bytes=256,
              max_bytes=128 * 1024 * 1024, structure="pdf"),
    Signature("zip", "zip", "archive", headers=(b"PK\x03\x04",),
              footer=b"PK\x05\x06", footer_tail=22, min_bytes=64,
              max_bytes=256 * 1024 * 1024, structure="zip",
              aliases=("docx", "xlsx", "pptx", "odt", "jar", "apk")),
    Signature("gzip", "gz", "archive", headers=(b"\x1f\x8b\x08",),
              min_bytes=32, max_bytes=256 * 1024 * 1024),
    Signature("7z", "7z", "archive", headers=(b"7z\xbc\xaf\x27\x1c",),
              min_bytes=64, max_bytes=256 * 1024 * 1024),
    Signature("rar", "rar", "archive",
              headers=(b"Rar!\x1a\x07\x00", b"Rar!\x1a\x07\x01\x00"),
              min_bytes=64, max_bytes=256 * 1024 * 1024),
    Signature("mp4", "mp4", "video", headers=(b"ftyp",), header_at=4,
              min_bytes=256, max_bytes=512 * 1024 * 1024, structure="mp4"),
    Signature("mp3", "mp3", "audio", headers=(b"ID3", b"\xff\xfb", b"\xff\xf3"),
              min_bytes=128, max_bytes=64 * 1024 * 1024),
    Signature("wav", "wav", "audio", headers=(b"RIFF",),
              min_bytes=64, max_bytes=256 * 1024 * 1024, structure="riff"),
    Signature("sqlite", "sqlite", "database", headers=(b"SQLite format 3\x00",),
              min_bytes=512, max_bytes=256 * 1024 * 1024),
]

# Longest header we need to keep as overlap between scan windows.
MAX_HEADER_LEN = max(
    sig.header_at + len(h) for sig in SIGNATURES for h in sig.headers
)


def match_at(buf: bytes, pos: int) -> Optional[Signature]:
    """Return the Signature whose header starts at buf[pos], or None."""
    for sig in SIGNATURES:
        start = pos + sig.header_at
        for header in sig.headers:
            if buf[start:start + len(header)] == header:
                return sig
    return None


def iter_header_hits(buf: bytes, base_offset: int = 0) -> Iterator[Tuple[int, Signature]]:
    """
    Yield (absolute_offset, Signature) for every header match in `buf`.

    `base_offset` is the position of buf[0] within the whole source, so the
    yielded offset is absolute.
    """
    limit = len(buf) - MAX_HEADER_LEN
    pos = 0
    while pos <= limit:
        sig = match_at(buf, pos)
        if sig is not None:
            yield base_offset + pos, sig
        pos += 1


def by_name(name: str) -> Optional[Signature]:
    key = name.strip().lower()
    for sig in SIGNATURES:
        if sig.name == key or key in sig.aliases:
            return sig
    return None
