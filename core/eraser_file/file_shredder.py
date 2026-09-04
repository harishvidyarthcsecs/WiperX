# wiperx/core/eraser_file/file_shredder.py
"""
File Shredder
-------------
Per-file secure deletion primitive.

shred_file() overwrites a regular file's byte length with random data
(optionally a trailing zero pass), fsyncs, truncates to zero, renames the
entry through several random names to obscure the original filename in the
directory, then unlinks it.

Scope and limits:
  - Operates on regular files only. Symlinks are not followed by default.
  - Reaches the file's own data blocks. It does NOT reach filesystem slack,
    journals, snapshots, or SSD over-provisioned areas - see trace_scrubber.
  - Expected IO errors (missing file, permission denied, locked) are captured
    in the ShredResult with ok=False; only programmer misuse raises.

NOTE: this is the Claude reference implementation so Phase 1 is demoable now.
The Codex Phase 1 prompt asks for an independent implementation plus the full
pytest matrix; keep whichever passes the matrix cleanly.
"""

from __future__ import annotations

import logging
import os
import secrets
import time
from dataclasses import dataclass
from typing import Optional

logger = logging.getLogger(__name__)

_DEFAULT_CHUNK = 1 << 20  # 1 MiB


@dataclass
class ShredResult:
    """Outcome of shredding a single file."""

    path: str
    size_bytes: int
    passes: int          # random overwrite passes actually written
    renames: int         # random rename rounds completed
    method: str          # "random+zero" | "random" | "zero" | "none"
    ok: bool
    error: Optional[str] = None
    duration_s: float = 0.0


def _overwrite(handle, length: int, source, step: int) -> None:
    """
    Write `length` bytes to an open file in `step`-sized writes.

    `source` is either raw `bytes` (repeated to fill, used for the zero pass)
    or a callable ``f(n) -> bytes`` returning exactly `n` fresh bytes per call
    (used for random passes, so a file larger than one buffer is not filled
    with a single repeating block).
    """
    handle.seek(0)
    remaining = length
    is_callable = callable(source)
    while remaining > 0:
        n = step if remaining >= step else remaining
        if is_callable:
            handle.write(source(n))
        else:
            handle.write(source if n >= len(source) else source[:n])
        remaining -= n
    handle.flush()
    os.fsync(handle.fileno())


def shred_file(
    path: str,
    *,
    passes: int = 1,
    zero_final: bool = True,
    rename_rounds: int = 3,
    chunk_size: int = _DEFAULT_CHUNK,
    follow_symlinks: bool = False,
) -> ShredResult:
    """
    Securely erase a single file.

    Args:
        path            : Path to the file to erase.
        passes          : Number of random-data overwrite passes (>= 1).
        zero_final      : Append a trailing all-zero pass.
        rename_rounds   : Random rename rounds before unlink (>= 0).
        chunk_size      : Overwrite buffer size in bytes.
        follow_symlinks : If False, a symlink target is left untouched.

    Returns:
        ShredResult

    Raises:
        ValueError : passes < 1 or rename_rounds < 0 or chunk_size < 1.
    """
    if passes < 1:
        raise ValueError("passes must be >= 1")
    if rename_rounds < 0:
        raise ValueError("rename_rounds must be >= 0")
    if chunk_size < 1:
        raise ValueError("chunk_size must be >= 1")

    started = time.perf_counter()
    result = ShredResult(
        path=path, size_bytes=0, passes=0, renames=0, method="none", ok=False
    )

    try:
        if os.path.islink(path) and not follow_symlinks:
            result.error = "symlink skipped"
            return _finish(result, started)

        if not os.path.isfile(path):
            result.error = "not a regular file"
            return _finish(result, started)

        size = os.path.getsize(path)
        result.size_bytes = size

        if not os.access(path, os.W_OK):
            try:
                os.chmod(path, 0o600)
            except OSError:
                pass  # best effort; the open below will report the real error

        buf_len = min(chunk_size, max(size, 1))
        with open(path, "r+b", buffering=0) as handle:
            for _ in range(passes):
                # Fresh randomness per chunk, not one repeated buffer.
                _overwrite(handle, size, os.urandom, buf_len)
                result.passes += 1
            if zero_final:
                _overwrite(handle, size, b"\x00" * buf_len, buf_len)
            os.ftruncate(handle.fileno(), 0)
            handle.flush()
            os.fsync(handle.fileno())

        result.method = "random+zero" if zero_final else "random"

        current = path
        parent = os.path.dirname(os.path.abspath(path)) or "."
        for _ in range(rename_rounds):
            new_path = os.path.join(parent, secrets.token_hex(16))
            os.rename(current, new_path)
            current = new_path
            result.renames += 1
            _fsync_dir(parent)

        os.remove(current)
        _fsync_dir(parent)
        result.ok = True

    except OSError as exc:
        result.error = f"{exc.__class__.__name__}: {exc}"
    return _finish(result, started)


def _fsync_dir(path: str) -> None:
    """fsync a directory so a rename/unlink is durable. Best effort."""
    try:
        dir_fd = os.open(path, os.O_RDONLY)
        try:
            os.fsync(dir_fd)
        finally:
            os.close(dir_fd)
    except OSError:
        pass


def _finish(result: ShredResult, started: float) -> ShredResult:
    result.duration_s = round(time.perf_counter() - started, 4)
    level = logging.INFO if result.ok else logging.WARNING
    logger.log(level, "[FileShredder] %s -> ok=%s error=%s",
               result.path, result.ok, result.error)
    return result
