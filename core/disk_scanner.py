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

macOS  : Uses `diskutil list -plist` + `diskutil info -plist <id>`
         - SolidState → SSD, BusProtocol → bus type
         - identifier is the whole-disk node (e.g. "disk2")

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
        is_system  : True if this disk contains the running OS; False if
                     confirmed not to; None if this could not be determined
                     (e.g. the root-device lookup failed) - callers MUST
                     treat None as "unsafe to wipe", never as False.
        is_mounted : True/False/None with the same fail-closed meaning as
                     is_system, for whether any partition is mounted.
        raw        : Original raw line/output for debugging
    """
    identifier: str
    model: str = "Unknown"
    serial: str = ""
    size_human: str = "Unknown"
    size_bytes: int = 0
    disk_type: str = "Unknown"
    bus_type: str = "Unknown"
    is_system: Optional[bool] = False
    is_mounted: Optional[bool] = False
    raw: str = ""
    partitions: List[str] = field(default_factory=list)
    # Set when this DiskInfo represents a single partition / slice (e.g.
    # "disk8s1") rather than a whole physical disk. parent_identifier names
    # the whole disk it belongs to.
    is_partition: bool = False
    parent_identifier: Optional[str] = None

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

    # Windows PowerShell command — structured output
    WINDOWS_GET_DISK_CMD = (
        "powershell -Command \""
        "Get-Disk | Select-Object Number,Model,SerialNumber,"
        "Size,BusType,OperationalStatus | ConvertTo-Csv -NoTypeInformation\""
    )

    # ENG-05: the disk backing the boot volume, found via the partition
    # mounted at %SystemDrive% - not assumed to be disk number 0.
    WINDOWS_GET_SYSTEM_DISK_CMD = (
        "powershell -Command \""
        "Get-Partition -DriveLetter ($env:SystemDrive.TrimEnd(':')) | "
        "Select-Object DiskNumber | ConvertTo-Csv -NoTypeInformation\""
    )

    # ENG-04: every partition's disk number + assigned drive letter, used to
    # derive is_mounted per disk instead of aliasing it to is_system.
    WINDOWS_GET_PARTITIONS_CMD = (
        "powershell -Command \""
        "Get-Partition | Select-Object DiskNumber,DriveLetter | "
        "ConvertTo-Csv -NoTypeInformation\""
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
        elif self.os_type == OSType.MACOS:
            return self._scan_macos()
        else:
            # ValueError, not RuntimeError: matches core.strategies.get_strategy's
            # convention for the same "unsupported OS" condition.
            raise ValueError(
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

        mounted_devices = self._get_mounted_linux()   # None => detection failed
        root_device = self._get_root_device_linux()   # None => detection failed
        root_base = self._base_device_name(root_device) if root_device else None

        # Fail closed (ENG-01 / ENG-02): if either detection mechanism itself
        # failed (missing df/awk/tail, unreadable /proc/mounts - not merely
        # "no match found"), every disk's system/mounted status is *unknown*,
        # not False. An unknown status must block the wipe, never silently
        # pass Safety Check 3/4 - see core.execution_manager's check right
        # after disk resolution.
        detection_failed = root_device is None or mounted_devices is None
        if detection_failed:
            logger.error(
                "[DiskScanner] Root-device or mount-table detection failed - "
                "system/mounted status for every disk will be reported as "
                "unknown (None) so callers refuse to wipe rather than guess."
            )

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

                if detection_failed:
                    is_system = None
                    is_mounted = None
                else:
                    # Exact whole-disk-name comparison (ENG-03): a substring
                    # check here ("sda" in "/dev/sda1") also matches unrelated
                    # devices whose name happens to be a substring of another
                    # (e.g. a mapper/LVM path), so compare the *base* device
                    # name derived from the root/mount path, not containment.
                    is_system = root_base is not None and name == root_base
                    is_mounted = any(
                        self._base_device_name(m) == name for m in mounted_devices
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

    def _get_mounted_linux(self) -> Optional[List[str]]:
        """List of currently mounted /dev/* paths, or None if detection failed."""
        try:
            output = self.executor.run_command(self.LINUX_MOUNT_CMD)
            return [line.split()[0] for line in output.splitlines() if line.startswith("/dev/")]
        except Exception as e:
            logger.warning(f"[DiskScanner] Could not read mounts: {e}")
            return None

    def _get_root_device_linux(self) -> Optional[str]:
        """Device path of the root filesystem, or None if detection failed."""
        try:
            result = self.executor.run_command(self.LINUX_ROOT_CMD).strip()
            return result or None
        except Exception as e:
            logger.warning(f"[DiskScanner] Could not determine root device: {e}")
            return None

    @staticmethod
    def _base_device_name(path: str) -> Optional[str]:
        """Whole-disk name from a device/partition path.

        '/dev/sda1' -> 'sda', '/dev/nvme0n1p1' -> 'nvme0n1',
        '/dev/mmcblk0p1' -> 'mmcblk0', '/dev/sda' -> 'sda'. Used for exact
        (not substring) matching against lsblk's whole-disk names - ENG-03.
        """
        if not path:
            return None
        base = path.rsplit("/", 1)[-1]
        m = re.match(r"^(nvme\d+n\d+|mmcblk\d+)p\d+$", base)
        if m:
            return m.group(1)
        m = re.match(r"^([a-zA-Z]+)\d+$", base)
        if m:
            return m.group(1)
        return base

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

        # ENG-04/ENG-05: mirror the Linux fail-closed pattern (ENG-01/02) -
        # a genuine detection failure (PowerShell error, unparseable output)
        # must mark every disk's system/mounted status as *unknown* (None),
        # never guess "disk 0 is system" or "is_mounted = is_system".
        system_disk_number = self._get_system_disk_number_windows()
        partitions = self._get_partitions_windows()
        detection_failed = system_disk_number is None or partitions is None
        if detection_failed:
            logger.error(
                "[DiskScanner] Windows system-disk or partition detection "
                "failed - system/mounted status for every disk will be "
                "reported as unknown (None) so callers refuse to wipe "
                "rather than guess."
            )

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

                # Determine disk type from bus
                if "nvme" in bus_type.lower():
                    disk_type = "NVMe"
                elif "usb" in bus_type.lower():
                    disk_type = "SSD"  # USB could be SSD or HDD; default SSD
                else:
                    disk_type = "HDD"  # Conservative default

                if detection_failed:
                    is_system = None
                    is_mounted = None
                else:
                    is_system = number == system_disk_number
                    is_mounted = any(
                        p_disk == number and p_letter for p_disk, p_letter in partitions
                    )

                disk = DiskInfo(
                    identifier=number,
                    model=model,
                    serial=serial,
                    size_human=self._bytes_to_human(size_bytes),
                    size_bytes=size_bytes,
                    disk_type=disk_type,
                    bus_type=bus_type,
                    is_system=is_system,
                    is_mounted=is_mounted,
                    raw=str(row),
                )
                disks.append(disk)
                logger.debug(f"[DiskScanner] Found disk: {disk.display_name()}")

        except Exception as e:
            logger.error(f"[DiskScanner] Failed to parse Windows disk output: {e}")

        logger.info(f"[DiskScanner] Windows scan complete: {len(disks)} disk(s) found.")
        return disks

    def _get_system_disk_number_windows(self) -> Optional[str]:
        """Disk number backing %SystemDrive%, or None if detection failed.

        ENG-05: this replaces the old "disk 0 is system" assumption, which
        is wrong on any multi-disk box where Windows isn't installed on the
        first enumerated disk.
        """
        import csv
        import io

        try:
            raw = self.executor.run_command(self.WINDOWS_GET_SYSTEM_DISK_CMD)
            if not raw:
                return None
            reader = csv.DictReader(io.StringIO(raw))
            for row in reader:
                number = (row.get("DiskNumber") or "").strip()
                if number:
                    return number
            return None
        except Exception as e:
            logger.warning(f"[DiskScanner] Could not determine Windows system disk: {e}")
            return None

    def _get_partitions_windows(self) -> Optional[List[tuple]]:
        """List of (disk_number, drive_letter) for every partition, or None
        if detection failed. ENG-04: used to derive is_mounted per disk
        instead of aliasing it to is_system."""
        import csv
        import io

        try:
            raw = self.executor.run_command(self.WINDOWS_GET_PARTITIONS_CMD)
            if not raw:
                return None
            reader = csv.DictReader(io.StringIO(raw))
            return [
                ((row.get("DiskNumber") or "").strip(), (row.get("DriveLetter") or "").strip())
                for row in reader
            ]
        except Exception as e:
            logger.warning(f"[DiskScanner] Could not enumerate Windows partitions: {e}")
            return None

    # ------------------------------------------------------------------
    # macOS Scanning
    # ------------------------------------------------------------------

    def _scan_macos(self) -> List[DiskInfo]:
        """Parse `diskutil` plist output and build DiskInfo list for macOS."""
        import plistlib

        try:
            raw_list = self.executor.run_command("diskutil list -plist")
            listing = plistlib.loads(self._as_bytes(raw_list))
        except Exception as e:
            logger.error(f"[DiskScanner] 'diskutil list' failed or unparseable: {e}")
            return []

        whole_disks = listing.get("WholeDisks") or []
        system_disks = self._get_system_whole_disks_macos()

        disks: List[DiskInfo] = []
        for ident in whole_disks:
            try:
                raw_info = self.executor.run_command(f"diskutil info -plist {ident}")
                info = plistlib.loads(self._as_bytes(raw_info))
            except Exception as e:
                logger.warning(f"[DiskScanner] 'diskutil info {ident}' failed: {e}")
                continue

            size_bytes = int(info.get("TotalSize") or info.get("Size") or 0)
            bus_raw = (info.get("BusProtocol") or "Unknown").strip()
            solid = bool(info.get("SolidState"))
            internal = bool(info.get("Internal"))
            removable = bool(info.get("RemovableMedia"))

            bus_upper = bus_raw.upper()
            if "USB" in bus_upper:
                bus_type = "USB"
            elif "SATA" in bus_upper:
                bus_type = "SATA"
            elif "THUNDERBOLT" in bus_upper:
                bus_type = "Thunderbolt"
            elif "APPLE FABRIC" in bus_upper:
                bus_type = "Apple Fabric"
            elif "PCI" in bus_upper:
                bus_type = "NVMe"
            elif "DISK IMAGE" in bus_upper:
                bus_type = "Disk Image"
            else:
                bus_type = bus_raw or "Unknown"

            if bus_type in ("NVMe", "Apple Fabric"):
                disk_type = "NVMe"
            elif solid:
                disk_type = "SSD"
            else:
                disk_type = "HDD"

            children = self._macos_children(ident, listing)
            is_mounted = bool((info.get("MountPoint") or "").strip()) or \
                any(c["mounted"] for c in children)

            # Safety: if we could not resolve the system disk(s), treat every
            # internal non-removable disk as system so it cannot be wiped.
            if system_disks:
                is_system = ident in system_disks
            else:
                is_system = internal and not removable

            disk = DiskInfo(
                identifier=ident,
                model=(info.get("MediaName") or info.get("IORegistryEntryName")
                       or "Unknown").strip() or "Unknown",
                serial=(info.get("DiskUUID") or "").strip(),
                size_human=self._bytes_to_human(size_bytes),
                size_bytes=size_bytes,
                disk_type=disk_type,
                bus_type=bus_type,
                is_system=is_system,
                is_mounted=is_mounted,
                raw=str(info),
                partitions=[c["id"] for c in children if c["id"]],
            )
            disks.append(disk)
            logger.debug(f"[DiskScanner] Found disk: {disk.display_name()}")

            # Also emit a DiskInfo per partition so callers can target a single
            # slice (e.g. `wipe disk8s1`) instead of the whole physical disk.
            for c in children:
                if not c["id"]:
                    continue
                disks.append(DiskInfo(
                    identifier=c["id"],
                    model=disk.model,
                    serial="",
                    size_human=self._bytes_to_human(c.get("size") or 0),
                    size_bytes=c.get("size") or 0,
                    disk_type=disk_type,
                    bus_type=bus_type,
                    is_system=is_system,       # never let a slice of the OS disk be wiped
                    is_mounted=bool(c["mounted"]),
                    raw="",
                    partitions=[],
                    is_partition=True,
                    parent_identifier=ident,
                ))

        logger.info(f"[DiskScanner] macOS scan complete: {len(disks)} disk(s) found.")
        return disks

    def _get_system_whole_disks_macos(self) -> set:
        """Whole-disk identifiers that back the running OS (root filesystem)."""
        import plistlib

        found: set = set()
        try:
            raw = self.executor.run_command("diskutil info -plist /")
            info = plistlib.loads(self._as_bytes(raw))
        except Exception as e:
            logger.warning(f"[DiskScanner] Could not resolve root device: {e}")
            return found

        parent = (info.get("ParentWholeDisk") or "").strip()
        if parent:
            found.add(self._whole_disk_id(parent))

        # The volume backing / is usually an APFS volume inside a synthesized
        # container; resolve the container's physical stores to the real disks.
        if parent:
            try:
                raw_c = self.executor.run_command(f"diskutil info -plist {parent}")
                cinfo = plistlib.loads(self._as_bytes(raw_c))
                for store in cinfo.get("APFSPhysicalStores") or []:
                    dev = (store.get("APFSPhysicalStore") or "").strip()
                    if dev:
                        found.add(self._whole_disk_id(dev))
            except Exception:  # noqa: BLE001 - best effort
                pass
        return found

    @staticmethod
    def _macos_children(ident: str, listing: dict) -> List[dict]:
        """[{id, mounted, size}] for the partitions / APFS volumes of one whole disk."""
        out: List[dict] = []
        for entry in listing.get("AllDisksAndPartitions") or []:
            if entry.get("DeviceIdentifier") != ident:
                continue
            parts = (entry.get("Partitions") or []) + (entry.get("APFSVolumes") or [])
            for part in parts:
                out.append({
                    "id": (part.get("DeviceIdentifier") or "").strip(),
                    "mounted": bool((part.get("MountPoint") or "").strip()),
                    "size": int(part.get("Size") or 0),
                })
        return out

    @staticmethod
    def _whole_disk_id(dev: str) -> str:
        """'disk0s2' / '/dev/disk0s2' -> 'disk0'."""
        m = re.search(r"(disk\d+)", dev)
        return m.group(1) if m else dev

    @staticmethod
    def _as_bytes(out) -> bytes:
        """Normalize an executor result (str or bytes) to bytes for plistlib."""
        if isinstance(out, bytes):
            return out
        return str(out).encode("utf-8", "replace")

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
