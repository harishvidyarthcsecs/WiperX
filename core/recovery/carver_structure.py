# wiperx/core/recovery/carver_structure.py
"""
Structural End-of-File Refinement
---------------------------------
Given a byte buffer that begins at a carved file header, parse the file's
internal structure to find its true end offset. This trims the
over-carving that a plain header->footer or header->max-size scan produces.

Every refiner returns the end offset RELATIVE to the buffer start, or None
when the structure is truncated / invalid (the caller then falls back to
footer scanning).

NOTE: Claude reference implementation. Codex builds an independent version.
"""

from __future__ import annotations

import logging
import struct
from typing import Callable, Dict, Optional

logger = logging.getLogger(__name__)


def _png(buf: bytes) -> Optional[int]:
    if buf[:8] != b"\x89PNG\r\n\x1a\n":
        return None
    pos = 8
    n = len(buf)
    while pos + 8 <= n:
        (length,) = struct.unpack(">I", buf[pos:pos + 4])
        ctype = buf[pos + 4:pos + 8]
        chunk_end = pos + 12 + length  # len + type + data + crc
        if chunk_end > n:
            return None
        if ctype == b"IEND":
            return chunk_end
        pos = chunk_end
    return None


def _jpeg(buf: bytes) -> Optional[int]:
    if buf[:2] != b"\xff\xd8":
        return None
    n = len(buf)
    pos = 2
    while pos + 1 < n:
        if buf[pos] != 0xFF:
            pos += 1
            continue
        marker = buf[pos + 1]
        if marker == 0xFF:
            pos += 1
            continue
        if marker == 0x00 or marker in range(0xD0, 0xD8):
            pos += 2
            continue
        if marker == 0xD9:  # EOI
            return pos + 2
        if marker == 0xDA:  # SOS -> entropy-coded data until next real marker
            pos += 2
            zrun = 0
            while pos + 1 < n:
                if buf[pos] == 0xFF and buf[pos + 1] not in (0x00, *range(0xD0, 0xD8)):
                    break
                # a long raw-zero run is not JPEG entropy - the file is
                # fragmented; let the bifragment carver handle it.
                zrun = zrun + 1 if buf[pos] == 0x00 else 0
                if zrun >= 24:
                    return None
                pos += 1
            continue
        if pos + 4 > n:
            return None
        (seg_len,) = struct.unpack(">H", buf[pos + 2:pos + 4])
        pos += 2 + seg_len
    return None


def _gif(buf: bytes) -> Optional[int]:
    if buf[:6] not in (b"GIF87a", b"GIF89a"):
        return None
    end = buf.find(b"\x00\x3b", 13)
    return end + 2 if end != -1 else None


def _bmp(buf: bytes) -> Optional[int]:
    if buf[:2] != b"BM" or len(buf) < 6:
        return None
    (size,) = struct.unpack("<I", buf[2:6])
    return size if 64 <= size <= len(buf) else None


def _zip(buf: bytes) -> Optional[int]:
    eocd = buf.rfind(b"PK\x05\x06")
    if eocd == -1 or eocd + 22 > len(buf):
        return None
    (comment_len,) = struct.unpack("<H", buf[eocd + 20:eocd + 22])
    end = eocd + 22 + comment_len
    return end if end <= len(buf) else eocd + 22


def _pdf(buf: bytes) -> Optional[int]:
    end = buf.rfind(b"%%EOF")
    if end == -1:
        return None
    end += 5
    while end < len(buf) and buf[end:end + 1] in (b"\r", b"\n"):
        end += 1
    return end


def _mp4(buf: bytes) -> Optional[int]:
    n = len(buf)
    pos = 0
    while pos + 8 <= n:
        (size,) = struct.unpack(">I", buf[pos:pos + 4])
        if size == 1:
            if pos + 16 > n:
                return None
            (size,) = struct.unpack(">Q", buf[pos + 8:pos + 16])
        elif size == 0:
            return n
        if size < 8 or pos + size > n:
            return pos if pos > 0 else None
        pos += size
    return pos if pos > 0 else None


def _riff(buf: bytes) -> Optional[int]:
    if buf[:4] != b"RIFF" or len(buf) < 8:
        return None
    (size,) = struct.unpack("<I", buf[4:8])
    end = 8 + size
    return end if 64 <= end <= len(buf) else None


_REFINERS: Dict[str, Callable[[bytes], Optional[int]]] = {
    "png": _png,
    "jpeg": _jpeg,
    "gif": _gif,
    "bmp": _bmp,
    "zip": _zip,
    "pdf": _pdf,
    "mp4": _mp4,
    "riff": _riff,
}


def refine_end(buf: bytes, structure: Optional[str]) -> Optional[int]:
    """
    Find the true end offset of the file that starts at buf[0].

    Args:
        buf       : bytes from the file header onwards (may include trailing
                    unrelated data).
        structure : refiner key from Signature.structure, or None.

    Returns:
        End offset relative to buf[0], or None if it cannot be determined.
    """
    if not structure:
        return None
    fn = _REFINERS.get(structure)
    if fn is None:
        return None
    try:
        return fn(buf)
    except (struct.error, IndexError, ValueError) as exc:  # malformed / truncated
        logger.debug("[carver_structure] %s refiner failed: %s", structure, exc)
        return None
