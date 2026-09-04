# wiperx/core/recovery/carver_header.py
"""
Signature-Based Carving Engine
------------------------------
Scan a source for file headers (core.recovery.signatures), then for each
hit determine the file end by, in order of preference:

  1. structural parse  (carver_structure.refine_end)
  2. footer magic scan
  3. header + max-size cap

Works with zero filesystem metadata. Optionally skips regions already
known to be allocated (so carving concentrates on unallocated space).

NOTE: Claude reference implementation. Codex builds an independent version.
"""

from __future__ import annotations

import hashlib
import logging
from dataclasses import dataclass, field
from pathlib import Path
from typing import Callable, List, Optional, Sequence, Tuple

from core import entropy
from core.recovery import carver_fragment, carver_structure
from core.recovery.signatures import MAX_HEADER_LEN, Signature, iter_header_hits

logger = logging.getLogger(__name__)

_WINDOW = 8 * 1024 * 1024
_PROBE_CAP = 48 * 1024 * 1024


@dataclass
class CarvedFile:
    """One file recovered by signature carving."""

    seq: int
    offset: int
    end: int
    sig_name: str
    ext: str
    category: str
    method: str            # "structure" | "footer" | "max-size"
    footer_found: bool
    sha256: str = ""
    path: str = ""
    size: int = 0
    notes: List[str] = field(default_factory=list)

    def __post_init__(self) -> None:
        if not self.size:
            self.size = self.end - self.offset


def _in_ranges(offset: int, ranges: Sequence[Tuple[int, int]]) -> bool:
    for start, stop in ranges:
        if start <= offset < stop:
            return True
    return False


def _valid_bmp_header(buf: bytes) -> bool:
    """A 2-byte 'BM' magic is far too weak; sanity-check the BMP file header."""
    if len(buf) < 14 or buf[:2] != b"BM":
        return False
    size = int.from_bytes(buf[2:6], "little")
    reserved = int.from_bytes(buf[6:10], "little")
    data_off = int.from_bytes(buf[10:14], "little")
    return reserved == 0 and 54 <= data_off < size <= (2 << 30)


def _valid_gzip_header(buf: bytes) -> bool:
    """3-byte gzip magic collides with random noise every ~16 MB on a large
    source. RFC 1952: the FLG byte's top 3 bits are reserved and must be 0
    in any real encoder's output."""
    if len(buf) < 4:
        return False
    flg = buf[3]
    return (flg & 0xE0) == 0


def _valid_mp3_header(buf: bytes) -> bool:
    """3-byte 'ID3' magic is just as weak as gzip's. ID3v2: version byte is
    2-4, flags' low nibble is reserved-zero, and the 4 size bytes are
    synchsafe (high bit of each clear)."""
    if len(buf) < 10 or buf[:3] != b"ID3":
        return False
    version = buf[3]
    flags = buf[5]
    if not (2 <= version <= 4) or (flags & 0x0F) != 0:
        return False
    return all((b & 0x80) == 0 for b in buf[6:10])


# Extra header validation for signatures whose magic is too short to trust alone.
_HEADER_GUARDS = {
    "bmp": _valid_bmp_header,
    "gzip": _valid_gzip_header,
    "mp3": _valid_mp3_header,
}

# Chunks sampled from a footerless probe to tell "genuinely no footer /
# fixed cap" from "magic collision sitting in wiped/filler space" before
# paying for the full hash+write.
_ENTROPY_SAMPLE_COUNT = 8
_ENTROPY_SAMPLE_SIZE = 4096


def _looks_like_filler(probe: bytes, header_len: int) -> bool:
    """
    True only when a footerless carve's body is homogeneous byte-fill
    (zeroed / fixed-fill) across evenly spaced samples - never for
    high-entropy content, since real compressed payloads (gzip/zip/mp3/7z)
    are themselves near-uniform-random by design and must not be discarded.
    """
    body = probe[header_len:]
    if len(body) <= _ENTROPY_SAMPLE_SIZE:
        return entropy.looks_wiped(body).verdict in ("zeroed", "fixed-fill")

    step = max(1, (len(body) - _ENTROPY_SAMPLE_SIZE) // _ENTROPY_SAMPLE_COUNT)
    for i in range(_ENTROPY_SAMPLE_COUNT):
        start = i * step
        chunk = body[start:start + _ENTROPY_SAMPLE_SIZE]
        if not chunk:
            break
        if entropy.looks_wiped(chunk).verdict not in ("zeroed", "fixed-fill"):
            return False
    return True


def _determine_end(source, offset: int, sig: Signature) -> Tuple[int, str, bool, bytes]:
    """Return (absolute_end, method, footer_found, probe_buf) for a header at `offset`."""
    probe_len = min(sig.max_bytes, _PROBE_CAP, source.size - offset)
    buf = source.read(offset, probe_len)

    end_rel = carver_structure.refine_end(buf, sig.structure)
    if end_rel and sig.min_bytes <= end_rel <= len(buf):
        return offset + end_rel, "structure", True, buf

    if sig.footer:
        fpos = buf.find(sig.footer, sig.min_bytes)
        if fpos != -1:
            # A long raw-zero run before the footer means a JPEG is
            # fragmented; skip the footer so the bifragment carver runs.
            if not (sig.name == "jpeg" and b"\x00" * 32 in buf[2:fpos]):
                end_rel = fpos + len(sig.footer) + sig.footer_tail
                return offset + min(end_rel, len(buf)), "footer", True, buf

    return offset + len(buf), "max-size", False, buf


def carve(
    source,
    out_dir: str,
    *,
    window: int = _WINDOW,
    allocated_ranges: Optional[Sequence[Tuple[int, int]]] = None,
    on_progress: Optional[Callable[[CarvedFile], None]] = None,
) -> List[CarvedFile]:
    """
    Carve files from `source` into `out_dir/recovered/`.

    Args:
        source           : core.recovery.acquire.Source.
        out_dir          : case directory; files land in `<out_dir>/recovered`.
        window           : header-scan window size in bytes.
        allocated_ranges : (start, stop) byte ranges to skip (already-allocated
                           filesystem data), or None to carve everything.
        on_progress      : called with each CarvedFile as it is written.

    Returns:
        list[CarvedFile] sorted by offset.
    """
    recovered = Path(out_dir) / "recovered"
    recovered.mkdir(parents=True, exist_ok=True)
    allocated = list(allocated_ranges or [])

    carved: List[CarvedFile] = []
    claimed: List[Tuple[int, int]] = []
    seq = 0
    scan_at = 0
    total = source.size

    while scan_at < total:
        read_len = min(window + MAX_HEADER_LEN, total - scan_at)
        chunk = source.read(scan_at, read_len)
        if not chunk:
            break

        for abs_off, sig in iter_header_hits(chunk, scan_at):
            if abs_off >= scan_at + window:
                continue  # belongs to the next window
            if _in_ranges(abs_off, claimed) or _in_ranges(abs_off, allocated):
                continue

            guard = _HEADER_GUARDS.get(sig.name)
            if guard is not None and not guard(source.read(abs_off, 32)):
                continue

            end, method, footer_found, probe = _determine_end(source, abs_off, sig)

            if method == "max-size" and _looks_like_filler(probe, MAX_HEADER_LEN):
                # Footerless carve whose body is homogeneous byte-fill, not
                # real file content (a real gzip/7z/rar/tiff/bmp/sqlite body
                # is never a uniform run of one byte). Skip the hash+write
                # entirely; claim just enough to avoid re-hitting this header.
                claimed.append((abs_off, abs_off + max(sig.min_bytes, MAX_HEADER_LEN)))
                continue

            carved_bytes = None
            frag_note = ""
            if method == "max-size" and sig.name == "jpeg":
                # footerless JPEG carve == probable fragmentation; try to
                # reassemble two fragments across a gap.
                frag = carver_fragment.carve_bifragment_jpeg(probe)
                if frag.recovered is not None:
                    carved_bytes = frag.recovered
                    method = "bifragment"
                    footer_found = True
                    end = abs_off + frag.frag2_start + frag.frag2_len
                    frag_note = (
                        f"bifragment reassembly: gap {frag.gap_start}..{frag.frag2_start} "
                        f"({frag.scan_candidates} splices tried)"
                    )

            size = len(carved_bytes) if carved_bytes is not None else end - abs_off
            if size < sig.min_bytes:
                continue

            seq += 1
            data = carved_bytes if carved_bytes is not None else source.read(abs_off, size)
            digest = hashlib.sha256(data).hexdigest()
            fname = f"{seq:06d}_{abs_off:012x}.{sig.ext}"
            fpath = recovered / fname
            fpath.write_bytes(data)

            cf = CarvedFile(
                seq=seq, offset=abs_off, end=end, sig_name=sig.name, ext=sig.ext,
                category=sig.category, method=method, footer_found=footer_found,
                sha256=digest, path=str(fpath), size=size,
            )
            if frag_note:
                cf.notes.append(frag_note)
            elif method == "max-size":
                cf.notes.append("no footer / structural end found; carve is size-capped")
            carved.append(cf)
            # A footerless, size-capped carve has no proven extent — claiming the
            # whole probe span would suppress every real header inside it. Claim
            # only enough to avoid re-hitting this same header.
            if method == "max-size":
                claimed.append((abs_off, abs_off + max(sig.min_bytes, MAX_HEADER_LEN)))
            else:
                claimed.append((abs_off, end))
            if on_progress:
                on_progress(cf)

        scan_at += window

    carved.sort(key=lambda c: c.offset)
    logger.info("[carver_header] carved %d file(s) from %s", len(carved), source.path)
    return carved
