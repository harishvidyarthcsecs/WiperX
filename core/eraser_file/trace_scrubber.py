# wiperx/core/eraser_file/trace_scrubber.py
"""
Residual-Trace Scrubber
-----------------------
After a file's contents are shredded and the file is unlinked, three
kinds of residue can remain on the medium:

  1. Free-space residue : data blocks of previously deleted files that
     were never overwritten. Cleared by filling all free space with a
     temporary file (NIST SP 800-88 "Clear" for logical media).
  2. TRIM residue       : on SSDs, telling the controller the blocks are
     free (`fstrim`) lets it garbage-collect the flash pages.
  3. File slack         : the tail of the last allocated block, between
     end-of-file and end-of-block. Only reachable by raw device writes,
     which are safe only when the filesystem is unmounted / read-only.

This module provides all three, with honest limitation reporting. It is
Linux-oriented; on other platforms the free-space fill still works, the
device-level helpers degrade to a "not supported" note.
"""

from __future__ import annotations

import logging
import os
import platform
import shutil
import subprocess
import tempfile
import time
from pathlib import Path
from typing import Callable, Optional

logger = logging.getLogger(__name__)

LogCB = Optional[Callable[[str], None]]
_DEFAULT_BLOCK_SIZE = 4096


def _log(message: str, log_callback: LogCB = None) -> None:
    logger.info("[TraceScrubber] %s", message)
    if log_callback:
        log_callback(f"[TraceScrubber] {message}")


def is_linux() -> bool:
    return platform.system() == "Linux"


# ---------------------------------------------------------------------------
# 1. Free-space fill
# ---------------------------------------------------------------------------

def wipe_free_space(
    mount_point: str,
    *,
    passes: int = 1,
    zero_final: bool = True,
    chunk_mib: int = 16,
    reserve_mib: int = 32,
    log_callback: LogCB = None,
) -> dict:
    """
    Overwrite all free space on the filesystem that hosts `mount_point`.

    Writes one or more temporary files full of random bytes (optionally a
    final zero pass), fsyncs, then deletes them. This destroys the block
    contents of files previously deleted with a plain `unlink`.

    Args:
        mount_point : Any path on the target filesystem (dir or file).
        passes      : Number of random-fill passes.
        zero_final  : Add a trailing all-zero pass after the random passes.
        chunk_mib   : Write buffer size in MiB.
        reserve_mib : Stop when free space falls below this, so the OS does
                      not wedge on a full filesystem.
        log_callback: Optional real-time log sink.

    Returns:
        dict: {mount_point, bytes_written, passes, zero_final, ok,
               error, duration_s, note}
    """
    result = {
        "mount_point": str(mount_point),
        "bytes_written": 0,
        "passes": 0,
        "zero_final": zero_final,
        "ok": False,
        "error": None,
        "duration_s": 0.0,
        "note": "",
    }
    started = time.perf_counter()

    base = Path(mount_point)
    target_dir = base if base.is_dir() else base.parent
    if not target_dir.is_dir():
        result["error"] = f"Not a directory: {target_dir}"
        return result

    chunk = b""
    reserve_bytes = reserve_mib * 1024 * 1024
    buf_bytes = max(1, chunk_mib) * 1024 * 1024
    total_written = 0
    pass_plan = ["random"] * max(1, passes) + (["zero"] if zero_final else [])

    _log(
        f"Filling free space on {target_dir} - {len(pass_plan)} pass(es), "
        f"reserving {reserve_mib} MiB. This temporarily consumes all free space.",
        log_callback,
    )

    try:
        for idx, mode in enumerate(pass_plan, start=1):
            chunk = b"\x00" * buf_bytes if mode == "zero" else os.urandom(buf_bytes)
            fd, tmp_path = tempfile.mkstemp(prefix=".wiperx_fill_", dir=target_dir)
            pass_written = 0
            try:
                with os.fdopen(fd, "wb", buffering=0) as handle:
                    while shutil.disk_usage(target_dir).free > reserve_bytes:
                        try:
                            handle.write(chunk)
                        except OSError as exc:  # ENOSPC despite the reserve check
                            if exc.errno == 28:
                                break
                            raise
                        pass_written += len(chunk)
                    handle.flush()
                    os.fsync(handle.fileno())
            finally:
                try:
                    os.unlink(tmp_path)
                except OSError:
                    pass
            total_written += pass_written
            if mode != "zero":
                result["passes"] = idx
            _log(f"Pass {idx} ({mode}): wrote {pass_written / 1e6:.1f} MB", log_callback)

        result["bytes_written"] = total_written
        result["ok"] = True
        result["note"] = (
            "Free-space blocks overwritten. Filesystem metadata (journal, "
            "directory entries, inode tables) is not reached by this method."
        )
    except OSError as exc:
        result["error"] = f"{exc.__class__.__name__}: {exc}"
        _log(f"ERROR: {result['error']}", log_callback)
    finally:
        del chunk
        result["duration_s"] = round(time.perf_counter() - started, 3)

    return result


# ---------------------------------------------------------------------------
# 2. TRIM
# ---------------------------------------------------------------------------

def fstrim(mount_point: str, log_callback: LogCB = None) -> dict:
    """
    Discard unused blocks on a mounted filesystem (SSD garbage collection).

    Args:
        mount_point : Mount point to trim.
        log_callback: Optional real-time log sink.

    Returns:
        dict: {ok, command, output, error, supported}
    """
    result = {"ok": False, "command": None, "output": "", "error": None, "supported": is_linux()}
    if not is_linux():
        result["error"] = "fstrim is Linux-only; skipped on " + platform.system()
        return result
    if shutil.which("fstrim") is None:
        result["error"] = "fstrim not found (install util-linux)"
        return result

    cmd = ["fstrim", "-v", str(mount_point)]
    result["command"] = " ".join(cmd)
    _log(f"Running: {result['command']}", log_callback)
    try:
        proc = subprocess.run(cmd, capture_output=True, text=True, timeout=1800, check=False)
        result["output"] = (proc.stdout + proc.stderr).strip()
        result["ok"] = proc.returncode == 0
        if not result["ok"]:
            result["error"] = f"fstrim exit {proc.returncode}: {result['output']}"
        _log(result["output"] or f"exit {proc.returncode}", log_callback)
    except (subprocess.SubprocessError, OSError) as exc:
        result["error"] = f"{exc.__class__.__name__}: {exc}"
        _log(f"ERROR: {result['error']}", log_callback)
    return result


# ---------------------------------------------------------------------------
# 3. File slack (device-level, offline only)
# ---------------------------------------------------------------------------

def containing_device(path: str) -> Optional[str]:
    """Return the block device backing `path` (e.g. /dev/sda1), or None."""
    if not is_linux() or shutil.which("df") is None:
        return None
    try:
        proc = subprocess.run(
            ["df", "--output=source", str(path)],
            capture_output=True, text=True, timeout=15, check=False,
        )
    except (subprocess.SubprocessError, OSError):
        return None
    lines = [ln.strip() for ln in proc.stdout.splitlines() if ln.strip()]
    if len(lines) >= 2 and lines[1].startswith("/dev/"):
        return lines[1]
    return None


def file_block_map(path: str) -> Optional[list]:
    """
    Physical extent map of `path` in 512-byte sectors on its block device.

    Uses `filefrag -b512 -e` (e2fsprogs). Returns a list of
    (physical_start_sector, length_sectors) tuples, or None if the tool is
    unavailable or the map cannot be parsed.
    """
    if not is_linux() or shutil.which("filefrag") is None:
        return None
    try:
        proc = subprocess.run(
            ["filefrag", "-b512", "-e", str(path)],
            capture_output=True, text=True, timeout=60, check=False,
        )
    except (subprocess.SubprocessError, OSError):
        return None
    if proc.returncode != 0:
        return None

    extents = []
    for line in proc.stdout.splitlines():
        parts = [p.strip().strip(":.") for p in line.split()]
        # Data rows look like: <ext> <logical> <physical> <expected|..> <length> <flags>
        if len(parts) < 5 or not parts[0].isdigit():
            continue
        try:
            physical_start = int(parts[2])
            length = int(parts[4])
        except ValueError:
            continue
        if length > 0:
            extents.append((physical_start, length))
    return extents or None


def zero_slack(
    path: str,
    *,
    block_size: int = _DEFAULT_BLOCK_SIZE,
    allow_raw: Optional[bool] = None,
    log_callback: LogCB = None,
) -> dict:
    """
    Best-effort zeroing of the file's last-block slack space.

    Slack lives outside the file's byte length, so it can only be reached by
    writing to the raw block device. That is safe only when the filesystem is
    unmounted or mounted read-only; on a live read-write mount the kernel may
    re-populate the page cache. This function therefore performs the raw write
    ONLY when explicitly allowed and running as root; otherwise it returns the
    computed slack details with a "not performed" note.

    Args:
        path        : Path to the (still-present) file whose slack to clear.
        block_size  : Filesystem block size in bytes.
        allow_raw   : Force-enable/disable the raw write. Default: enabled when
                      env WIPERX_ALLOW_RAW_SLACK=1.
        log_callback: Optional real-time log sink.

    Returns:
        dict: {performed, method, slack_bytes, device, extents, note, error}
    """
    result = {
        "performed": False,
        "method": "none",
        "slack_bytes": 0,
        "device": None,
        "extents": None,
        "note": "",
        "error": None,
    }

    try:
        size = os.path.getsize(path)
    except OSError as exc:
        result["error"] = f"cannot stat {path}: {exc}"
        return result

    remainder = size % block_size
    slack = 0 if remainder == 0 else block_size - remainder
    result["slack_bytes"] = slack
    if slack == 0:
        result["note"] = "File length is block-aligned; no slack to clear."
        result["performed"] = True
        result["method"] = "not-needed"
        return result

    if allow_raw is None:
        allow_raw = os.environ.get("WIPERX_ALLOW_RAW_SLACK") == "1"

    device = containing_device(path)
    extents = file_block_map(path)
    result["device"] = device
    result["extents"] = extents

    is_root = hasattr(os, "geteuid") and os.geteuid() == 0
    if not (is_linux() and allow_raw and is_root and device and extents):
        result["note"] = (
            f"{slack} bytes of slack detected but not cleared. Raw slack wiping "
            "needs Linux + root + WIPERX_ALLOW_RAW_SLACK=1 + an unmounted or "
            "read-only filesystem. Run 'wipe-free' on the mount instead, or wipe "
            "the whole device offline."
        )
        _log(result["note"], log_callback)
        return result

    last_start, last_len = extents[-1]
    slack_offset = (last_start + last_len) * 512 - slack
    try:
        fd = os.open(device, os.O_WRONLY)
        try:
            os.lseek(fd, slack_offset, os.SEEK_SET)
            os.write(fd, b"\x00" * slack)
            os.fsync(fd)
        finally:
            os.close(fd)
    except OSError as exc:
        result["error"] = f"raw slack write failed: {exc}"
        _log(f"ERROR: {result['error']}", log_callback)
        return result

    result["performed"] = True
    result["method"] = "raw-device-zero"
    result["note"] = f"Zeroed {slack} bytes of slack at {device} offset {slack_offset}."
    _log(result["note"], log_callback)
    return result
