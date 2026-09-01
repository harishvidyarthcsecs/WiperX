# wiperx/core/disk_scanner.py
"""
Disk Scanner
------------
Scans and enumerates disks on local or remote targets.

Linux  : Uses `lsblk -d -o NAME,ROTA,TRAN,SIZE,MODEL,SERIAL`
         - ROTA=1 → HDD, ROTA=0 → SSD/NVMe
         - TRAN: usb, sata, nvme

Windows: Uses PowerShell `Get-Disk` to enumerate disk objects
         - BusType: USB, SATA, NVMe, SCSI
         - Returns disk number, model, size, bus type

The scanner normalizes output into a uniform DiskInfo dataclass
regardless of the underlying OS.
"""

import logging
import re
from dataclasses import dataclass, field
from typing import List, Optional

logger = logging.getLogger(__name__)


# ---------------------------------------------------------------------------
# Data Model
# ---------------------------------------------------------------------------

@dataclass
class DiskInfo:
    """
    Normalized representation of a disk on any supported OS.

    Attributes:
        identifier : Linux device name (e.g. "sda") or Windows disk number (e.g. "0")
        model      : Manufacturer model string
        serial     : Serial number (may be empty if not accessible)
        size_human : Human-readable size string (e.g. "500G")
        size_bytes : Size in bytes (0 if unknown)
        disk_type  : "HDD", "SSD", "NVMe", or "Unknown"
        bus_type   : "SATA", "USB", "NVMe", "SCSI", or "Unknown"
        is_system  : True if this disk contains the running OS
        is_mounted : True if any partition of this disk is currently mounted
        raw        : Original raw line/output for debugging
    """
    identifier: str
    model: str = "Unknown"
    serial: str = ""
    size_human: str = "Unknown"
    size_bytes: int = 0
    disk_type: str = "Unknown"
    bus_type: str = "Unknown"
    is_system: bool = False
    is_mounted: bool = False
    raw: str = ""
    partitions: List[str] = field(default_factory=list)

    def display_name(self) -> str:
        """Returns a human-readable identifier string."""
        return f"{self.identifier} ({self.model}, {self.size_human}, {self.disk_type})"


# ---------------------------------------------------------------------------
# Scanner
# ---------------------------------------------------------------------------

class DiskScanner:
    """
    Scans disks on a target (local or remote) via an executor.

    Usage:
        scanner = DiskScanner(executor=local_executor, os_type=OSType.LINUX)
        disks = scanner.scan()
    """

    # Linux lsblk command — outputs tab-separated values
    LINUX_LSBLK_CMD = (
        "lsblk -d -o NAME,ROTA,TRAN,SIZE,MODEL,SERIAL --noheadings --bytes"
    )

    # Windows PowerShell command — joins Get-Disk with Get-PhysicalDisk for an
    # accurate media type, and flags the disk that hosts the system drive.
    WINDOWS_GET_DISK_CMD = (
        "powershell -NoProfile -Command \""
        "$s=(Get-Partition | Where-Object {$_.DriveLetter -eq "
        "$env:SystemDrive.Substring(0,1)}).DiskNumber; "
        "Get-Disk | ForEach-Object { $p=Get-PhysicalDisk -DeviceNumber $_.Number "
        "-ErrorAction SilentlyContinue; [PSCustomObject]@{Number=$_.Number;"
        "Model=$_.Model;SerialNumber=$_.SerialNumber;Size=$_.Size;"
        "BusType=$_.BusType;MediaType=$p.MediaType;IsBoot=$_.IsBoot;"
        "IsSystem=($_.Number -eq $s);OperationalStatus=$_.OperationalStatus} } "
        "| ConvertTo-Csv -NoTypeInformation\""
    )

    # Linux command to check mounted devices
    LINUX_MOUNT_CMD = "cat /proc/mounts"

    # Linux command to identify root device
    LINUX_ROOT_CMD = "df / | tail -1 | awk '{print $1}'"

    def __init__(self, executor, os_type):
        """
        Args:
            executor : An executor instance (LocalExecutor, SSHExecutor, WinRMExecutor).
            os_type  : OSType enum value.
        """
        self.executor = executor
        self.os_type = os_type

    def scan(self) -> List[DiskInfo]:
        """
        Scan all available disks on the target.

        Returns:
            List[DiskInfo]: List of discovered disks.

        Raises:
            RuntimeError: If scanning fails or OS is unsupported.
        """
        from core.os_detector import OSType

        logger.info(f"[DiskScanner] Starting disk scan (OS: {self.os_type})")

        if self.os_type == OSType.LINUX:
            return self._scan_linux()
        elif self.os_type == OSType.WINDOWS:
            return self._scan_windows()
        elif self.os_type == OSType.DARWIN:
            return self._scan_macos()
        else:
            raise RuntimeError(
                f"[DiskScanner] Unsupported OS type: {self.os_type}. "
                "Cannot perform disk scan."
            )

    # ------------------------------------------------------------------
    # Linux Scanning
    # ------------------------------------------------------------------

    def _scan_linux(self) -> List[DiskInfo]:
        """Parse lsblk output and build DiskInfo list for Linux."""
        raw_output = self.executor.run_command(self.LINUX_LSBLK_CMD)
        if not raw_output:
            logger.error("[DiskScanner] lsblk returned no output.")
            return []

        mounted_devices = self._get_mounted_linux()
        root_device = self._get_root_device_linux()

        disks = []
        for line in raw_output.strip().splitlines():
            parts = line.split()
            if len(parts) < 3:
                continue

            try:
                name = parts[0]          # e.g. "sda"
                rota = parts[1]          # "1" = HDD, "0" = SSD/NVMe
                tran = parts[2]          # sata / usb / nvme / ""
                size_bytes = int(parts[3]) if parts[3].isdigit() else 0
                model = " ".join(parts[4:-1]) if len(parts) > 5 else (parts[4] if len(parts) > 4 else "Unknown")
                serial = parts[-1] if len(parts) > 5 else ""

                # Determine disk type
                if "nvme" in tran.lower():
                    disk_type = "NVMe"
                    bus_type = "NVMe"
                elif rota == "1":
                    disk_type = "HDD"
                    bus_type = tran.upper() if tran else "Unknown"
                else:
                    disk_type = "SSD"
                    bus_type = tran.upper() if tran else "Unknown"

                if "usb" in tran.lower():
                    bus_type = "USB"

                # Determine system disk (contains root partition)
                is_system = (
                    f"/dev/{name}" in (root_device or "") or
                    root_device is not None and name in root_device
                )

                # Determine if mounted
                is_mounted = any(
                    f"/dev/{name}" in m for m in mounted_devices
                )

                disk = DiskInfo(
                    identifier=name,
                    model=model,
                    serial=serial,
                    size_human=self._bytes_to_human(size_bytes),
                    size_bytes=size_bytes,
                    disk_type=disk_type,
                    bus_type=bus_type,
                    is_system=is_system,
                    is_mounted=is_mounted,
                    raw=line,
                )
                disks.append(disk)
                logger.debug(f"[DiskScanner] Found disk: {disk.display_name()}")

            except (IndexError, ValueError) as e:
                logger.warning(f"[DiskScanner] Failed to parse lsblk line '{line}': {e}")

        logger.info(f"[DiskScanner] Linux scan complete: {len(disks)} disk(s) found.")
        return disks

    def _get_mounted_linux(self) -> List[str]:
        """Return list of currently mounted device paths."""
        try:
            output = self.executor.run_command(self.LINUX_MOUNT_CMD)
            return [line.split()[0] for line in output.splitlines() if line.startswith("/dev/")]
        except Exception as e:
            logger.warning(f"[DiskScanner] Could not read mounts: {e}")
            return []

    def _get_root_device_linux(self) -> Optional[str]:
        """Return the device path of the root filesystem."""
        try:
            return self.executor.run_command(self.LINUX_ROOT_CMD).strip()
        except Exception as e:
            logger.warning(f"[DiskScanner] Could not determine root device: {e}")
            return None

    # ------------------------------------------------------------------
    # Windows Scanning
    # ------------------------------------------------------------------

    def _scan_windows(self) -> List[DiskInfo]:
        """Parse Get-Disk PowerShell CSV output and build DiskInfo list."""
        raw_output = self.executor.run_command(self.WINDOWS_GET_DISK_CMD)
        if not raw_output:
            logger.error("[DiskScanner] Get-Disk returned no output.")
            return []

        import csv
        import io

        disks = []
        try:
            reader = csv.DictReader(io.StringIO(raw_output))
            for row in reader:
                number = row.get("Number", "?").strip()
                model = row.get("Model", "Unknown").strip()
                serial = row.get("SerialNumber", "").strip()
                size_bytes_raw = row.get("Size", "0").strip()
                bus_type = row.get("BusType", "Unknown").strip()
                status = row.get("OperationalStatus", "Unknown").strip()

                # Parse size
                try:
                    size_bytes = int(size_bytes_raw)
                except ValueError:
                    size_bytes = 0

                media_type = row.get("MediaType", "").strip().lower()
                is_boot = row.get("IsBoot", "").strip().lower() == "true"
                is_system = row.get("IsSystem", "").strip().lower() == "true"
                # Fallback for the older Select-Object form with no IsSystem col.
                if "IsSystem" not in row and "IsBoot" not in row:
                    is_system = (number == "0")

                # Determine disk type: MediaType (Get-PhysicalDisk) wins, then bus.
                if "ssd" in media_type or media_type == "4":
                    disk_type = "NVMe" if "nvme" in bus_type.lower() else "SSD"
                elif "hdd" in media_type or media_type == "3":
                    disk_type = "HDD"
                elif "nvme" in bus_type.lower():
                    disk_type = "NVMe"
                elif "usb" in bus_type.lower():
                    disk_type = "SSD"
                else:
                    disk_type = "HDD"

                disk = DiskInfo(
                    identifier=number,
                    model=model,
                    serial=serial,
                    size_human=self._bytes_to_human(size_bytes),
                    size_bytes=size_bytes,
                    disk_type=disk_type,
                    bus_type=bus_type,
                    is_system=is_system or is_boot,
                    is_mounted=is_system or is_boot,
                    raw=str(row),
                )
                disks.append(disk)
                logger.debug(f"[DiskScanner] Found disk: {disk.display_name()}")

        except Exception as e:
            logger.error(f"[DiskScanner] Failed to parse Windows disk output: {e}")

        logger.info(f"[DiskScanner] Windows scan complete: {len(disks)} disk(s) found.")
        return disks

    # ------------------------------------------------------------------
    # macOS Scanning
    # ------------------------------------------------------------------

    MACOS_LIST_CMD = "diskutil list -plist"
    MACOS_INFO_CMD = "diskutil info -plist {ident}"
    MACOS_ROOT_CMD = "diskutil info -plist /"
    MACOS_MOUNT_CMD = "mount"

    def _scan_macos(self) -> List[DiskInfo]:
        """Enumerate whole disks via `diskutil` plist output."""
        import plistlib

        raw_list = self.executor.run_command(self.MACOS_LIST_CMD)
        if not raw_list:
            logger.error("[DiskScanner] diskutil list returned no output.")
            return []

        try:
            listing = plistlib.loads(raw_list.encode("utf-8", "replace"))
        except Exception as e:  # noqa: BLE001
            logger.error(f"[DiskScanner] Could not parse diskutil list plist: {e}")
            return []

        whole = listing.get("WholeDisks") or []
        root_whole = self._macos_root_whole_disk()
        mount_blob = ""
        try:
            mount_blob = self.executor.run_command(self.MACOS_MOUNT_CMD) or ""
        except Exception:  # noqa: BLE001
            pass

        disks: List[DiskInfo] = []
        for ident in whole:
            info = {}
            try:
                info_raw = self.executor.run_command(
                    self.MACOS_INFO_CMD.format(ident=ident)
                )
                info = plistlib.loads(info_raw.encode("utf-8", "replace"))
            except Exception as e:  # noqa: BLE001
                logger.warning(f"[DiskScanner] diskutil info {ident} failed: {e}")

            size_bytes = int(info.get("Size") or info.get("TotalSize") or 0)
            model = (info.get("MediaName") or info.get("IORegistryEntryName")
                     or "Unknown")
            serial = info.get("DiskUUID", "") or ""
            protocol = (info.get("BusProtocol") or info.get("Protocol") or "").lower()
            solid_state = bool(info.get("SolidState"))

            if "nvme" in protocol or "pci" in protocol:
                disk_type, bus_type = ("NVMe", "NVMe") if solid_state else ("SSD", "PCIe")
            elif "usb" in protocol:
                disk_type, bus_type = ("SSD" if solid_state else "HDD"), "USB"
            elif "thunderbolt" in protocol:
                disk_type, bus_type = ("SSD" if solid_state else "HDD"), "Thunderbolt"
            elif solid_state:
                disk_type, bus_type = "SSD", (protocol.upper() or "SATA")
            else:
                disk_type, bus_type = "HDD", (protocol.upper() or "SATA")

            is_system = bool(root_whole) and ident == root_whole
            is_mounted = (
                bool(info.get("MountPoint"))
                or ("/dev/%s" % ident) in mount_blob
                or ("/dev/%ss" % ident) in mount_blob  # diskNsM slices
            )

            disks.append(DiskInfo(
                identifier=ident,
                model=model,
                serial=serial,
                size_human=self._bytes_to_human(size_bytes),
                size_bytes=size_bytes,
                disk_type=disk_type,
                bus_type=bus_type,
                is_system=is_system,
                is_mounted=is_mounted,
                raw=str(info) if info else ident,
            ))

        logger.info(f"[DiskScanner] macOS scan complete: {len(disks)} disk(s) found.")
        return disks

    def _macos_root_whole_disk(self) -> Optional[str]:
        """Whole-disk identifier backing the `/` filesystem (e.g. 'disk0')."""
        import plistlib

        try:
            raw = self.executor.run_command(self.MACOS_ROOT_CMD)
            info = plistlib.loads(raw.encode("utf-8", "replace"))
            return (info.get("ParentWholeDisk")
                    or info.get("APFSContainerReference")
                    or None)
        except Exception as e:  # noqa: BLE001
            logger.warning(f"[DiskScanner] Could not resolve macOS root disk: {e}")
            return None

    # ------------------------------------------------------------------
    # Helpers
    # ------------------------------------------------------------------

    @staticmethod
    def _bytes_to_human(size_bytes: int) -> str:
        """Convert bytes to human-readable string."""
        if size_bytes == 0:
            return "Unknown"
        for unit in ["B", "KB", "MB", "GB", "TB"]:
            if size_bytes < 1024.0:
                return f"{size_bytes:.1f} {unit}"
            size_bytes /= 1024.0
        return f"{size_bytes:.1f} PB"
