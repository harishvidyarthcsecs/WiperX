# wiperx/core/eraser_file/verify.py
"""
Erase Verification
------------------
Independent confirmation that a secure file/folder erase actually removed
the data from the medium.

Two checks are provided:

  scan_device_for_marker() : stream the raw device or image looking for a
      known plaintext marker that was present in the erased file. A clean
      erase means the marker is gone. This is the programmatic form of
      `grep -a MARKER /dev/sdX` and works on both devices and image files.

  verify_extents_zeroed()  : sample sectors across a file's former physical
      extents (from trace_scrubber.file_block_map) and confirm they read as
      zero. Meaningful only when the filesystem is quiescent / offline.

Neither check can prove unrecoverability on flash media with wear-levelling;
they verify the logical medium, in line with NIST SP 800-88 "Clear".
"""

from __future__ import annotations

import logging
import random
import time
from typing import Callable, Optional, Sequence

logger = logging.getLogger(__name__)

LogCB = Optional[Callable[[str], None]]
_SECTOR = 512


def _log(message: str, log_callback: LogCB = None) -> None:
    logger.info("[EraseVerify] %s", message)
    if log_callback:
        log_callback(f"[EraseVerify] {message}")


def scan_device_for_marker(
    source: str,
    marker: bytes,
    *,
    max_bytes: Optional[int] = None,
    chunk_mib: int = 8,
    log_callback: LogCB = None,
) -> dict:
    """
    Search a raw device or image file for a byte marker.

    Args:
        source    : Path to a block device or image file.
        marker    : The byte string that must NOT be found for a clean erase.
        max_bytes : Stop after scanning this many bytes (None = whole source).
        chunk_mib : Read buffer size in MiB.
        log_callback: Optional real-time log sink.

    Returns:
        dict: {source, marker_found, first_offset, bytes_scanned,
               duration_s, ok, error}
    """
    result = {
        "source": str(source),
        "marker_found": None,
        "first_offset": None,
        "bytes_scanned": 0,
        "duration_s": 0.0,
        "ok": False,
        "error": None,
    }
    if not marker:
        result["error"] = "marker must be a non-empty byte string"
        return result

    started = time.perf_counter()
    buf_size = max(1, chunk_mib) * 1024 * 1024
    overlap = len(marker) - 1
    scanned = 0
    carry = b""

    try:
        with open(source, "rb", buffering=0) as handle:
            while True:
                if max_bytes is not None and scanned >= max_bytes:
                    break
                to_read = buf_size
                if max_bytes is not None:
                    to_read = min(buf_size, max_bytes - scanned)
                block = handle.read(to_read)
                if not block:
                    break
                window = carry + block
                pos = window.find(marker)
                if pos != -1:
                    result["marker_found"] = True
                    result["first_offset"] = scanned - len(carry) + pos
                    result["bytes_scanned"] = scanned + len(block)
                    result["ok"] = True
                    _log(
                        f"Marker FOUND at offset {result['first_offset']} in {source}",
                        log_callback,
                    )
                    result["duration_s"] = round(time.perf_counter() - started, 3)
                    return result
                scanned += len(block)
                carry = window[-overlap:] if overlap > 0 else b""

        result["marker_found"] = False
        result["bytes_scanned"] = scanned
        result["ok"] = True
        _log(f"Marker not present after scanning {scanned / 1e6:.1f} MB of {source}",
             log_callback)
    except OSError as exc:
        result["error"] = f"{exc.__class__.__name__}: {exc}"
        _log(f"ERROR: {result['error']}", log_callback)
    finally:
        result["duration_s"] = round(time.perf_counter() - started, 3)

    return result


def verify_extents_zeroed(
    device: str,
    extents: Sequence,
    *,
    samples: int = 64,
    marker: Optional[bytes] = None,
    log_callback: LogCB = None,
) -> dict:
    """
    Sample sectors across physical extents and confirm they read as zero.

    Args:
        device  : Block device / image backing the extents.
        extents : Iterable of (start_sector, length_sectors) in 512-byte units,
                  as returned by trace_scrubber.file_block_map().
        samples : Number of random sectors to read across all extents.
        marker  : If given, also fail when this byte string appears in a sample.
        log_callback: Optional real-time log sink.

    Returns:
        dict: {verified, sampled_sectors, nonzero_sectors, marker_found,
               method, details}
    """
    result = {
        "verified": False,
        "sampled_sectors": 0,
        "nonzero_sectors": 0,
        "marker_found": False,
        "method": "extent-sector-sampling",
        "details": "",
    }
    extent_list = [(int(s), int(n)) for s, n in extents if int(n) > 0]
    if not extent_list:
        result["details"] = "No extents supplied."
        return result

    sector_pool = []
    for start, length in extent_list:
        # cap per-extent enumeration to keep the pool bounded
        for offset in range(0, min(length, 8192)):
            sector_pool.append(start + offset)
    if not sector_pool:
        result["details"] = "Extent list produced no sectors."
        return result

    pick = min(samples, len(sector_pool))
    chosen = random.sample(sector_pool, pick)
    nonzero = 0

    try:
        with open(device, "rb", buffering=0) as handle:
            for sec in chosen:
                handle.seek(sec * _SECTOR)
                data = handle.read(_SECTOR)
                if data and any(data):
                    nonzero += 1
                if marker and data and marker in data:
                    result["marker_found"] = True
    except OSError as exc:
        result["details"] = f"{exc.__class__.__name__}: {exc}"
        _log(f"ERROR: {result['details']}", log_callback)
        return result

    result["sampled_sectors"] = pick
    result["nonzero_sectors"] = nonzero
    result["verified"] = nonzero == 0 and not result["marker_found"]
    result["details"] = (
        f"Sampled {pick} sectors across {len(extent_list)} extent(s); "
        f"{nonzero} non-zero; marker_found={result['marker_found']}."
    )
    _log(result["details"], log_callback)
    return result
