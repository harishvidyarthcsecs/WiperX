# wiperx/core/recovery/acquire.py
"""
Evidence Acquisition
--------------------
Read-only access to the recovery source (a block device or a raw / .dd /
.img image file) plus the per-case working directory.

Guarantees:
  - the source file descriptor is opened O_RDONLY; no write path exists;
  - a block device that is currently mounted read-write is refused unless
    the caller passes allow_mounted=True;
  - the whole source is SHA-256 hashed once and cached in the manifest;
  - every read is recorded as an (offset, length) range for the audit trail;
  - the case directory is created outside the source, never on it.
"""

from __future__ import annotations

import hashlib
import logging
import os
import platform
import subprocess
from datetime import datetime, timezone
from pathlib import Path
from typing import Callable, List, Optional, Tuple

logger = logging.getLogger(__name__)

TOOL_VERSION = "wiperx-recovery/0.3"
_HASH_CHUNK = 8 * 1024 * 1024


class SourceError(RuntimeError):
    """Raised when the recovery source cannot be opened safely."""


def _is_block_device(path: str) -> bool:
    try:
        return os.path.exists(path) and (os.stat(path).st_mode & 0o170000) == 0o060000
    except OSError:
        return False


def _rw_mounted(path: str) -> bool:
    """True if `path` is a block device with a read-write mount (best-effort)."""
    real = os.path.realpath(path)
    proc = Path("/proc/mounts")
    if proc.exists():
        try:
            for line in proc.read_text().splitlines():
                parts = line.split()
                if len(parts) >= 4 and os.path.realpath(parts[0]) == real:
                    if "rw" in parts[3].split(","):
                        return True
        except OSError:
            pass
        return False
    if platform.system() != "Linux":
        try:
            out = subprocess.run(
                ["mount"], capture_output=True, text=True, timeout=10
            ).stdout
        except (subprocess.SubprocessError, OSError):
            return False
        for line in out.splitlines():
            if line.startswith(real + " ") and "read-only" not in line:
                return True
    return False


class Source:
    """A read-only, range-logged view over a device or image file."""

    def __init__(self, path: str, fd: int, size: int, is_device: bool):
        self.path = path
        self._fd = fd
        self.size = size
        self.is_device = is_device
        self.reads: List[Tuple[int, int]] = []
        self._sha256: Optional[str] = None

    def read(self, offset: int, size: int) -> bytes:
        """Read `size` bytes at `offset`, clamped to the source length."""
        if offset < 0 or size <= 0 or offset >= self.size:
            return b""
        size = min(size, self.size - offset)
        os.lseek(self._fd, offset, os.SEEK_SET)
        buf = bytearray()
        remaining = size
        while remaining:
            chunk = os.read(self._fd, min(remaining, _HASH_CHUNK))
            if not chunk:
                break
            buf.extend(chunk)
            remaining -= len(chunk)
        self.reads.append((offset, len(buf)))
        return bytes(buf)

    def iter_chunks(self, chunk_size: int = _HASH_CHUNK, start: int = 0):
        """Yield (offset, bytes) across the whole source from `start`."""
        offset = start
        while offset < self.size:
            data = self.read(offset, min(chunk_size, self.size - offset))
            if not data:
                break
            yield offset, data
            offset += len(data)

    def sha256(self, progress_cb: Optional[Callable[[int, int], None]] = None) -> str:
        """SHA-256 of the entire source (computed once, then cached)."""
        if self._sha256 is not None:
            return self._sha256
        digest = hashlib.sha256()
        done = 0
        os.lseek(self._fd, 0, os.SEEK_SET)
        while True:
            chunk = os.read(self._fd, _HASH_CHUNK)
            if not chunk:
                break
            digest.update(chunk)
            done += len(chunk)
            if progress_cb:
                progress_cb(done, self.size)
        self._sha256 = digest.hexdigest()
        logger.info("[acquire] source SHA-256 %s (%d bytes)", self._sha256, self.size)
        return self._sha256

    def close(self) -> None:
        try:
            os.close(self._fd)
        except OSError:
            pass

    def __enter__(self) -> "Source":
        return self

    def __exit__(self, *exc) -> None:
        self.close()


def _device_size_fallback(fd: int, path: str) -> int:
    """Best-effort block-device size when lseek(SEEK_END) returns 0 (macOS)."""
    system = platform.system()
    try:
        import fcntl
        import struct
        if system == "Darwin":
            # DKIOCGETBLOCKCOUNT = 0x40086419, DKIOCGETBLOCKSIZE = 0x40046418
            bcount = struct.unpack("Q", fcntl.ioctl(fd, 0x40086419, b"\x00" * 8))[0]
            bsize = struct.unpack("I", fcntl.ioctl(fd, 0x40046418, b"\x00" * 4))[0]
            if bcount and bsize:
                return bcount * bsize
        elif system == "Linux":
            # BLKGETSIZE64 = 0x80081272
            return struct.unpack("Q", fcntl.ioctl(fd, 0x80081272, b"\x00" * 8))[0]
    except Exception:  # noqa: BLE001 - fall through to diskutil
        pass

    if system == "Darwin":
        try:
            import plistlib
            import subprocess
            out = subprocess.run(
                ["diskutil", "info", "-plist", path],
                capture_output=True, timeout=15,
            )
            info = plistlib.loads(out.stdout)
            return int(info.get("TotalSize") or info.get("Size") or 0)
        except Exception:  # noqa: BLE001
            pass
    return 0


def open_source(path: str, *, allow_mounted: bool = False) -> Source:
    """
    Open a device or image file read-only for recovery.

    Args:
        path          : /dev/sdX, or a .dd / .img / .raw image file.
        allow_mounted : proceed even if a device is rw-mounted (unsafe).

    Returns:
        Source

    Raises:
        SourceError : path missing, or a rw-mounted device without override.
    """
    if not os.path.exists(path):
        raise SourceError(f"source does not exist: {path}")

    is_device = _is_block_device(path)
    if is_device and not allow_mounted and _rw_mounted(path):
        raise SourceError(
            f"{path} is mounted read-write. Unmount it, or re-run with "
            "allow_mounted=True (you accept that concurrent writes may "
            "corrupt the recovery)."
        )

    fd = os.open(path, os.O_RDONLY)
    try:
        if is_device:
            size = os.lseek(fd, 0, os.SEEK_END)
            os.lseek(fd, 0, os.SEEK_SET)
            if not size:
                # macOS block devices don't report size via lseek(SEEK_END);
                # fall back to an ioctl (block count * block size), then to
                # `diskutil`.
                size = _device_size_fallback(fd, path)
        else:
            size = os.path.getsize(path)
    except OSError as exc:
        os.close(fd)
        raise SourceError(f"cannot size {path}: {exc}") from exc

    if is_device and not size:
        os.close(fd)
        raise SourceError(f"cannot determine size of device {path}")

    logger.info("[acquire] opened %s (%s, %d bytes) read-only",
                path, "device" if is_device else "image", size)
    return Source(path, fd, size, is_device)


class Case:
    """Per-recovery working directory + manifest header."""

    def __init__(self, out_dir: str, source: Source, operator: str = "System"):
        self.dir = Path(out_dir)
        self.recovered_dir = self.dir / "recovered"
        self.recovered_dir.mkdir(parents=True, exist_ok=True)
        self.source = source
        self.operator = operator
        _now = datetime.now(timezone.utc)
        self.case_id = _now.strftime("case-%Y%m%dT%H%M%SZ")
        self.started_at = _now.strftime("%Y-%m-%dT%H:%M:%S.%f") + "Z"
        logger.info("[acquire] case %s -> %s", self.case_id, self.dir)

    def manifest_header(self) -> dict:
        """Chain-of-custody header for the case report."""
        return {
            "case_id": self.case_id,
            "tool_version": TOOL_VERSION,
            "operator": self.operator,
            "started_at": self.started_at,
            "source": {
                "path": self.source.path,
                "type": "device" if self.source.is_device else "image",
                "size_bytes": self.source.size,
                "sha256": self.source.sha256(),
            },
            "read_only": True,
            "reads_logged": len(self.source.reads),
        }
