# wiperx/core/platform/base.py  (package: core.platform)
"""
Platform adapters
-----------------
Small, testable seam for the handful of things that genuinely differ per OS and
were previously spread through `if os_type == ...` ladders and bare
`platform.system()` checks:

  - is_admin()        : are we running with the privilege a wipe needs?
  - elevate_hint()    : how the operator gets that privilege on this OS
  - raw_device_path() : the path used for raw block IO for a disk identifier
  - protect_key_file(): lock down the signing key at rest

Disk scanning and wipe-strategy selection still live in `core.disk_scanner` /
`core.strategies` (each with an added branch per OS); this module is only the
cross-cutting bits.
"""

from __future__ import annotations

import os
import platform
import subprocess
from typing import Optional

from core.os_detector import OSType


class PlatformAdapter:
    os_type: OSType = OSType.UNSUPPORTED

    # -- privilege ---------------------------------------------------------
    def is_admin(self) -> bool:
        raise NotImplementedError

    def elevate_hint(self) -> str:
        return "Run WiperX with elevated privileges."

    # -- devices ---------------------------------------------------------
    def raw_device_path(self, identifier: str) -> str:
        """Absolute path for raw IO against a disk identifier (e.g. 'sda')."""
        raise NotImplementedError

    # -- key at rest ---------------------------------------------------------
    def protect_key_file(self, path: str) -> None:
        """Best-effort: restrict the signing key to the current user only."""
        try:
            os.chmod(path, 0o600)
        except OSError:
            pass


class _PosixMixin:
    def is_admin(self) -> bool:
        return hasattr(os, "geteuid") and os.geteuid() == 0

    def elevate_hint(self) -> str:
        return "Re-run with sudo (root privileges required)."


class LinuxAdapter(_PosixMixin, PlatformAdapter):
    os_type = OSType.LINUX

    def raw_device_path(self, identifier: str) -> str:
        if identifier.startswith("/"):
            return identifier
        return f"/dev/{identifier}"


class DarwinAdapter(_PosixMixin, PlatformAdapter):
    os_type = OSType.DARWIN

    def raw_device_path(self, identifier: str) -> str:
        # Prefer the raw (unbuffered) node for whole-disk IO.
        if identifier.startswith("/dev/"):
            leaf = identifier.split("/dev/", 1)[1]
        elif identifier.startswith("/"):
            return identifier
        else:
            leaf = identifier
        if leaf.startswith("disk"):
            leaf = "r" + leaf
        return f"/dev/{leaf}"

    def protect_key_file(self, path: str) -> None:
        super().protect_key_file(path)
        # chflags is a no-op if it fails; chmod already did the real work.
        subprocess.run(["chflags", "uchg", path], check=False,
                       capture_output=True)


class WindowsAdapter(PlatformAdapter):
    os_type = OSType.WINDOWS

    def is_admin(self) -> bool:
        try:
            import ctypes

            return ctypes.windll.shell32.IsUserAnAdmin() != 0
        except Exception:
            return False

    def elevate_hint(self) -> str:
        return "Run WiperX from an elevated PowerShell (Run as administrator)."

    def raw_device_path(self, identifier: str) -> str:
        # Accept 'PhysicalDrive0', '0', or a already-qualified \\.\ path.
        if identifier.startswith("\\\\.\\"):
            return identifier
        if identifier.isdigit():
            return rf"\\.\PhysicalDrive{identifier}"
        return rf"\\.\{identifier}"

    def protect_key_file(self, path: str) -> None:
        # chmod only toggles the read-only bit on Windows; use icacls to strip
        # inheritance and grant the current user alone.
        user = os.environ.get("USERNAME") or os.environ.get("USER") or ""
        try:
            subprocess.run(["icacls", path, "/inheritance:r"], check=False,
                           capture_output=True)
            if user:
                subprocess.run(["icacls", path, "/grant:r", f"{user}:F"],
                               check=False, capture_output=True)
        except FileNotFoundError:
            pass


_ADAPTERS = {
    OSType.LINUX: LinuxAdapter,
    OSType.DARWIN: DarwinAdapter,
    OSType.WINDOWS: WindowsAdapter,
}


def get_adapter(os_type: Optional[OSType] = None) -> PlatformAdapter:
    """Return the adapter for `os_type`, or for the local machine if omitted."""
    if os_type is None:
        sysname = platform.system().lower()
        os_type = {
            "linux": OSType.LINUX,
            "darwin": OSType.DARWIN,
            "windows": OSType.WINDOWS,
        }.get(sysname, OSType.UNSUPPORTED)

    cls = _ADAPTERS.get(os_type)
    if cls is None:
        raise ValueError(f"No platform adapter for {os_type}")
    return cls()
