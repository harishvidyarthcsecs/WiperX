# wiperx/core/eraser_file/batch.py
"""
Batch Eraser
------------
Expand a list of file/folder paths, shred every regular file over a thread
pool, remove the emptied directory tree, and aggregate the outcome.

Non-file entries (symlinks, FIFOs, sockets, device nodes) and directories
supplied without `recursive` are recorded as failed ShredResults with an
explanatory error rather than silently skipped.

NOTE: Claude reference implementation - see file_shredder.py header.
"""

from __future__ import annotations

import logging
import os
import stat
import time
from concurrent.futures import ThreadPoolExecutor
from dataclasses import dataclass
from typing import Callable, Iterable, List, Optional

from core.eraser_file.file_shredder import ShredResult, shred_file

logger = logging.getLogger(__name__)


@dataclass
class BatchSummary:
    """Aggregate outcome of a batch erase run."""

    total: int
    succeeded: int
    failed: int
    bytes_erased: int
    results: List[ShredResult]
    duration_s: float


def _classify(path: str, recursive: bool):
    """Return (files_to_shred, skipped_results) for a single input path."""
    files: list = []
    skipped: list = []
    try:
        st = os.lstat(path)
    except OSError as exc:
        skipped.append(ShredResult(path, 0, 0, 0, "none", False, f"lstat failed: {exc}"))
        return files, skipped

    mode = st.st_mode
    if stat.S_ISLNK(mode):
        skipped.append(ShredResult(path, 0, 0, 0, "none", False, "symlink skipped"))
    elif stat.S_ISREG(mode):
        files.append(path)
    elif stat.S_ISDIR(mode):
        if not recursive:
            skipped.append(
                ShredResult(path, 0, 0, 0, "none", False, "directory skipped (non-recursive)")
            )
        else:
            for root, _dirs, names in os.walk(path, topdown=False):
                for name in names:
                    child = os.path.join(root, name)
                    if os.path.islink(child):
                        skipped.append(
                            ShredResult(child, 0, 0, 0, "none", False, "symlink skipped")
                        )
                    elif os.path.isfile(child):
                        files.append(child)
                    else:
                        skipped.append(
                            ShredResult(child, 0, 0, 0, "none", False, "special file skipped")
                        )
    else:
        skipped.append(
            ShredResult(path, 0, 0, 0, "none", False, "special file skipped (fifo/socket/device)")
        )
    return files, skipped


def _prune_dirs(roots: Iterable[str]) -> None:
    """Remove now-empty directory trees under the given input roots."""
    for root in roots:
        if not os.path.isdir(root):
            continue
        for cur, _dirs, _names in os.walk(root, topdown=False):
            try:
                os.rmdir(cur)
            except OSError:
                pass  # not empty / not permitted - leave it
        try:
            os.rmdir(root)
        except OSError:
            pass


def shred_paths(
    paths: Iterable[str],
    *,
    recursive: bool = True,
    workers: int = 4,
    on_progress: Optional[Callable[[ShredResult], None]] = None,
    **shred_kwargs,
) -> BatchSummary:
    """
    Shred every regular file reachable from `paths`.

    Args:
        paths       : File/folder paths to erase.
        recursive   : Recurse into directories.
        workers     : Thread pool size.
        on_progress : Called with each ShredResult as it completes.
        shred_kwargs: Forwarded to file_shredder.shred_file
                      (passes, zero_final, rename_rounds, chunk_size, ...).

    Returns:
        BatchSummary with results sorted by path.
    """
    started = time.perf_counter()
    input_roots = [str(p) for p in paths]

    to_shred: list = []
    results: list = []
    for root in input_roots:
        files, skipped = _classify(root, recursive)
        to_shred.extend(files)
        results.extend(skipped)
        for sk in skipped:
            if on_progress:
                on_progress(sk)

    # macOS writes an AppleDouble "._name" sidecar next to each file on
    # FAT/exFAT volumes holding the resource fork + Finder metadata. Shred it
    # alongside its parent so a "secure erase" does not leave it behind.
    for f in list(to_shred):
        base = os.path.basename(f)
        if base.startswith("._"):
            continue
        sidecar = os.path.join(os.path.dirname(f), "._" + base)
        if os.path.isfile(sidecar) and not os.path.islink(sidecar):
            to_shred.append(sidecar)

    # de-duplicate while preserving determinism
    to_shred = sorted(set(to_shred))

    if to_shred:
        with ThreadPoolExecutor(max_workers=max(1, workers)) as pool:
            futures = {pool.submit(shred_file, f, **shred_kwargs): f for f in to_shred}
            for future in futures:
                res = future.result()
                results.append(res)
                if on_progress:
                    on_progress(res)

    _prune_dirs(input_roots)

    results.sort(key=lambda r: r.path)
    succeeded = sum(1 for r in results if r.ok)
    failed = len(results) - succeeded
    bytes_erased = sum(r.size_bytes for r in results if r.ok)

    summary = BatchSummary(
        total=len(results),
        succeeded=succeeded,
        failed=failed,
        bytes_erased=bytes_erased,
        results=results,
        duration_s=round(time.perf_counter() - started, 4),
    )
    logger.info(
        "[BatchEraser] total=%d succeeded=%d failed=%d bytes=%d in %.2fs",
        summary.total, summary.succeeded, summary.failed,
        summary.bytes_erased, summary.duration_s,
    )
    return summary
