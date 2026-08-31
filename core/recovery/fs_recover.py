# wiperx/core/recovery/fs_recover.py
"""
Filesystem-Aware Undelete
-------------------------
Recover files whose directory entry / inode / MFT record still points at
their data blocks (the "pressed Delete", "emptied Recycle Bin", "quick
format" cases). Full filename, path and timestamps survive here.

Backends, in order:
  1. pytsk3            - The Sleuth Kit Python bindings.
  2. fls / icat        - The Sleuth Kit command-line tools.
  3. unavailable       - returns available=False with a note; the carver
                         path still runs.

NOTE: Claude-owned. Reference-quality; allocated-range extraction (to let
the carver skip live data) is left as a follow-up - it currently returns
an empty list, so the carver scans the whole source.
"""

from __future__ import annotations

import hashlib
import logging
import os
import re
import shutil
import subprocess
from dataclasses import dataclass, field
from pathlib import Path
from typing import List, Tuple

logger = logging.getLogger(__name__)

try:
    import pytsk3

    _PYTSK3_OK = True
except Exception:  # pragma: no cover - libtsk missing
    _PYTSK3_OK = False

_SAFE = re.compile(r"[^A-Za-z0-9._-]+")


@dataclass
class FsRecoveryResult:
    """Outcome of the filesystem-aware pass."""

    available: bool
    backend: str                       # "pytsk3" | "tsk-cli" | "none"
    records: List[dict] = field(default_factory=list)
    allocated_ranges: List[Tuple[int, int]] = field(default_factory=list)
    note: str = ""


def _safe_name(name: str, inode) -> str:
    base = _SAFE.sub("_", name).strip("_") or "file"
    return f"{inode}_{base}"[:200]


# ---------------------------------------------------------------------------
# pytsk3 backend
# ---------------------------------------------------------------------------

def _open_fs(path: str):
    """Return a pytsk3.FS_Info, trying a bare FS then the first partition."""
    img = pytsk3.Img_Info(path)
    try:
        return pytsk3.FS_Info(img, offset=0)
    except Exception:
        pass
    try:
        vol = pytsk3.Volume_Info(img)
        for part in vol:
            if part.len > 2 and not part.desc.startswith(b"Unallocated"):
                try:
                    return pytsk3.FS_Info(img, offset=part.start * 512)
                except Exception:
                    continue
    except Exception:
        pass
    raise RuntimeError("no readable filesystem found on source")


def _walk_pytsk3(fs, directory, out_dir: Path, parent: str, records: List[dict],
                 seen: set, depth: int = 0) -> None:
    if depth > 24:
        return
    for entry in directory:
        if not hasattr(entry, "info") or entry.info.name is None:
            continue
        name = entry.info.name.name.decode("utf-8", "replace")
        if name in (".", ".."):
            continue
        meta = entry.info.meta
        rel = f"{parent}/{name}".lstrip("/")

        is_dir = meta and meta.type == pytsk3.TSK_FS_META_TYPE_DIR
        if is_dir:
            try:
                _walk_pytsk3(fs, entry.as_directory(), out_dir, rel, records, seen, depth + 1)
            except Exception:
                pass
            continue

        if meta is None:
            continue
        deleted = bool(entry.info.name.flags & pytsk3.TSK_FS_NAME_FLAG_UNALLOC) or \
            bool(meta.flags & pytsk3.TSK_FS_META_FLAG_UNALLOC)
        if not deleted or meta.size <= 0:
            continue

        key = (int(meta.addr), name)
        if key in seen:
            continue
        seen.add(key)

        try:
            data = entry.read_random(0, min(meta.size, 512 * 1024 * 1024))
        except Exception as exc:  # noqa: BLE001
            logger.debug("[fs_recover] read failed %s: %s", rel, exc)
            continue

        fname = _safe_name(name, meta.addr)
        fpath = out_dir / fname
        fpath.write_bytes(data)
        records.append({
            "source_method": "fs",
            "backend": "pytsk3",
            "inode": int(meta.addr),
            "original_name": name,
            "original_path": rel,
            "size": len(data),
            "sha256": hashlib.sha256(data).hexdigest(),
            "recovered_name": fname,
            "recovered_path": str(fpath),
            "data_readable": len(data) == meta.size,
            "timestamps": {
                "mtime": getattr(meta, "mtime", 0),
                "atime": getattr(meta, "atime", 0),
                "ctime": getattr(meta, "ctime", 0),
                "crtime": getattr(meta, "crtime", 0),
            },
        })


def _recover_pytsk3(path: str, out_dir: Path) -> FsRecoveryResult:
    try:
        fs = _open_fs(path)
    except Exception as exc:  # noqa: BLE001
        return FsRecoveryResult(False, "none", note=f"pytsk3: {exc}")
    records: List[dict] = []
    try:
        _walk_pytsk3(fs, fs.open_dir(path="/"), out_dir, "", records, set())
    except Exception as exc:  # noqa: BLE001
        return FsRecoveryResult(False, "none", note=f"pytsk3 walk failed: {exc}")
    plural = "ry" if len(records) == 1 else "ries"
    return FsRecoveryResult(True, "pytsk3", records=records,
                            note=f"{len(records)} deleted ent{plural} recovered")


# ---------------------------------------------------------------------------
# TSK command-line backend
# ---------------------------------------------------------------------------

_FLS_DELETED = re.compile(r"^[a-z-]/[a-z-]\s+\*\s+(\d+)(?:-\d+-\d+)?:\s+(.*)$")


def _recover_tsk_cli(path: str, out_dir: Path) -> FsRecoveryResult:
    if not (shutil.which("fls") and shutil.which("icat")):
        return FsRecoveryResult(False, "none", note="fls/icat not installed")
    try:
        proc = subprocess.run(
            ["fls", "-r", "-p", "-d", path],
            capture_output=True, text=True, timeout=600, check=False,
        )
    except (subprocess.SubprocessError, OSError) as exc:
        return FsRecoveryResult(False, "none", note=f"fls failed: {exc}")

    records: List[dict] = []
    for line in proc.stdout.splitlines():
        m = _FLS_DELETED.match(line.strip())
        if not m:
            continue
        inode, name = m.group(1), m.group(2).strip()
        try:
            data = subprocess.run(
                ["icat", path, inode], capture_output=True, timeout=300, check=False
            ).stdout
        except (subprocess.SubprocessError, OSError):
            continue
        if not data:
            continue
        fname = _safe_name(os.path.basename(name), inode)
        fpath = out_dir / fname
        fpath.write_bytes(data)
        records.append({
            "source_method": "fs",
            "backend": "tsk-cli",
            "inode": int(inode),
            "original_name": os.path.basename(name),
            "original_path": name,
            "size": len(data),
            "sha256": hashlib.sha256(data).hexdigest(),
            "recovered_name": fname,
            "recovered_path": str(fpath),
            "data_readable": True,
            "timestamps": {},
        })
    return FsRecoveryResult(True, "tsk-cli", records=records,
                            note=f"{len(records)} deleted entries via fls/icat")


# ---------------------------------------------------------------------------
# public entrypoint
# ---------------------------------------------------------------------------

def recover_filesystem(source_path: str, out_dir: str) -> FsRecoveryResult:
    """
    Run the filesystem-aware undelete pass.

    Args:
        source_path : device or image path.
        out_dir     : case directory; files land in `<out_dir>/recovered`.

    Returns:
        FsRecoveryResult (available=False when no backend is present).
    """
    recovered = Path(out_dir) / "recovered"
    recovered.mkdir(parents=True, exist_ok=True)

    if _PYTSK3_OK:
        result = _recover_pytsk3(source_path, recovered)
        if result.available:
            logger.info("[fs_recover] pytsk3: %s", result.note)
            return result
        logger.info("[fs_recover] pytsk3 unusable (%s); trying tsk-cli", result.note)

    result = _recover_tsk_cli(source_path, recovered)
    if result.available:
        logger.info("[fs_recover] tsk-cli: %s", result.note)
        return result

    note = ("filesystem-aware recovery unavailable - install 'sleuthkit' "
            "(fls/icat) or the pytsk3 Python package. Carving still runs.")
    logger.warning("[fs_recover] %s", note)
    return FsRecoveryResult(False, "none", note=note)
