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

            end, method, footer_found, probe = _determine_end(source, abs_off, sig)

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
            claimed.append((abs_off, end))
            if on_progress:
                on_progress(cf)

        scan_at += window

    carved.sort(key=lambda c: c.offset)
    logger.info("[carver_header] carved %d file(s) from %s", len(carved), source.path)
    return carved
