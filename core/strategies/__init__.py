# wiperx/core/strategies/__init__.py
"""
Wipe Strategy Layer
-------------------
All wipe logic is centralized here. Neither the CLI nor Flask
contains any wipe commands — they only call strategies.

Strategies:
  - LinuxHDDWipeStrategy  : shred -n 1 -z /dev/sdX
  - LinuxSSDWipeStrategy  : blkdiscard + dd zero pass
  - LinuxNVMeWipeStrategy : nvme format --ses=1
  - LinuxUSBWipeStrategy  : dd if=/dev/zero of=/dev/sdX bs=1M
  - WindowsWipeStrategy   : diskpart clean all

Each strategy implements the WipeStrategy base class with a
single `execute(disk, executor, log_callback)` method.
"""

import logging
from abc import ABC, abstractmethod
from typing import Callable, Optional

logger = logging.getLogger(__name__)


# ---------------------------------------------------------------------------
# Base Strategy
# ---------------------------------------------------------------------------

class WipeStrategy(ABC):
    """
    Abstract base class for all disk wipe strategies.
    All concrete strategies MUST inherit from this class.
    """

    name: str = "BaseStrategy"
    description: str = "Abstract wipe strategy"

    @abstractmethod
    def execute(
        self,
        disk,
        executor,
        log_callback: Optional[Callable[[str], None]] = None,
    ) -> bool:
        """
        Execute the wipe strategy on the given disk.

        Args:
            disk         : DiskInfo object describing the target disk.
            executor     : Executor instance to run commands.
            log_callback : Optional callable to receive real-time log lines.

        Returns:
            bool: True if wipe succeeded, False otherwise.
        """
        pass

    def _log(self, message: str, log_callback: Optional[Callable] = None):
        """Helper to log both to logger and optional callback."""
        logger.info(f"[{self.name}] {message}")
        if log_callback:
            log_callback(f"[{self.name}] {message}")


# ---------------------------------------------------------------------------
# Linux HDD Strategy — shred
# ---------------------------------------------------------------------------

class LinuxHDDWipeStrategy(WipeStrategy):
    """
    Wipe Linux HDD using GNU shred.
    Performs 1 random pass followed by a zero pass to obscure wiping.

    Command: shred -v -n 1 -z /dev/sdX

    Suitable for: Magnetic HDDs connected via SATA or USB.
    NOT suitable for SSDs (causes unnecessary wear; shred is ineffective on
    wear-levelled flash storage due to remapping).
    """

    name = "LinuxHDD-Shred"
    description = "1-pass random + zero overwrite using GNU shred (HDD)"

    def execute(self, disk, executor, log_callback=None) -> bool:
        device_path = f"/dev/{disk.identifier}"
        cmd = f"shred -v -n 1 -z {device_path}"

        self._log(f"Starting shred on {device_path}", log_callback)
        self._log(f"Command: {cmd}", log_callback)

        try:
            result = executor.run_command(cmd, timeout=3600)
            self._log(f"shred output: {result}", log_callback)
            self._log(f"Wipe complete on {device_path}", log_callback)
            return True
        except Exception as e:
            self._log(f"ERROR: shred failed on {device_path}: {e}", log_callback)
            return False


# ---------------------------------------------------------------------------
# Linux SSD Strategy — blkdiscard + zero pass
# ---------------------------------------------------------------------------

class LinuxSSDWipeStrategy(WipeStrategy):
    """
    Wipe Linux SSD using blkdiscard (ATA Secure Erase hint) + dd zero pass.

    Note: True ATA Secure Erase requires hdparm and a frozen-state workaround.
    blkdiscard is the safe, widely-supported alternative for SATA SSDs.
    For maximum compliance, use hdparm --security-erase in a live environment.

    Commands:
        blkdiscard /dev/sdX         (discard all blocks — TRIM)
        dd if=/dev/zero of=/dev/sdX bs=4M status=progress
    """

    name = "LinuxSSD-BlkDiscard"
    description = "Block discard + zero pass for SATA SSDs"

    def execute(self, disk, executor, log_callback=None) -> bool:
        device_path = f"/dev/{disk.identifier}"
        success = True

        # Step 1: blkdiscard
        cmd_discard = f"blkdiscard {device_path}"
        self._log(f"Step 1: blkdiscard on {device_path}", log_callback)
        self._log(f"Command: {cmd_discard}", log_callback)
        try:
            out = executor.run_command(cmd_discard, timeout=600)
            self._log(f"blkdiscard output: {out}", log_callback)
        except Exception as e:
            self._log(f"WARNING: blkdiscard failed (non-fatal): {e}", log_callback)
            # blkdiscard may not be supported on all SSDs; continue to dd pass

        # Step 2: zero pass
        cmd_dd = f"dd if=/dev/zero of={device_path} bs=4M status=progress conv=fsync"
        self._log(f"Step 2: dd zero pass on {device_path}", log_callback)
        self._log(f"Command: {cmd_dd}", log_callback)
        try:
            out = executor.run_command(cmd_dd, timeout=7200)
            self._log(f"dd output: {out}", log_callback)
            self._log(f"Wipe complete on {device_path}", log_callback)
        except Exception as e:
            self._log(f"ERROR: dd zero pass failed: {e}", log_callback)
            success = False

        return success


# ---------------------------------------------------------------------------
# Linux NVMe Strategy — nvme format
# ---------------------------------------------------------------------------

class LinuxNVMeWipeStrategy(WipeStrategy):
    """
    Wipe NVMe SSD using the nvme-cli format command.

    nvme format --ses=1 instructs the controller to perform a cryptographic
    erase (User Data Erase). This is the recommended method for NVMe drives
    as it is both fast and cryptographically secure.

    Requires: nvme-cli package installed on target.
    Command: nvme format /dev/nvme0n1 --ses=1 --force
    """

    name = "LinuxNVMe-Format"
    description = "NVMe controller User Data Erase via nvme-cli (NVMe SSD)"

    def execute(self, disk, executor, log_callback=None) -> bool:
        # NVMe device paths: /dev/nvme0n1, /dev/nvme1n1, etc.
        # The identifier may be "nvme0n1" or "nvme0" — normalize it
        identifier = disk.identifier
        if not identifier.startswith("nvme"):
            identifier = f"nvme0n1"  # fallback

        device_path = f"/dev/{identifier}"
        cmd = f"nvme format {device_path} --ses=1 --force"

        self._log(f"Starting NVMe format on {device_path}", log_callback)
        self._log(f"Command: {cmd}", log_callback)
        self._log(
            "NOTE: nvme format performs a controller-level cryptographic erase.",
            log_callback
        )

        try:
            result = executor.run_command(cmd, timeout=300)
            self._log(f"nvme format output: {result}", log_callback)
            self._log(f"NVMe wipe complete on {device_path}", log_callback)
            return True
        except Exception as e:
            self._log(f"ERROR: nvme format failed on {device_path}: {e}", log_callback)
            return False


# ---------------------------------------------------------------------------
# Linux USB Strategy — dd zero
# ---------------------------------------------------------------------------

class LinuxUSBWipeStrategy(WipeStrategy):
    """
    Wipe USB drive using dd with /dev/zero.

    USB drives (flash-based) do not reliably respond to shred due to
    wear-levelling, but a full zero pass overwrites all addressable sectors.

    Command: dd if=/dev/zero of=/dev/sdX bs=1M status=progress
    """

    name = "LinuxUSB-DD"
    description = "Full zero overwrite via dd (USB drives)"

    def execute(self, disk, executor, log_callback=None) -> bool:
        device_path = f"/dev/{disk.identifier}"
        cmd = f"dd if=/dev/zero of={device_path} bs=1M status=progress conv=fsync"

        self._log(f"Starting USB wipe via dd on {device_path}", log_callback)
        self._log(f"Command: {cmd}", log_callback)

        try:
            result = executor.run_command(cmd, timeout=7200)
            self._log(f"dd output: {result}", log_callback)
            self._log(f"USB wipe complete on {device_path}", log_callback)
            return True
        except Exception as e:
            self._log(f"ERROR: dd wipe failed on {device_path}: {e}", log_callback)
            return False


# ---------------------------------------------------------------------------
# Windows Wipe Strategy — diskpart
# ---------------------------------------------------------------------------

class WindowsWipeStrategy(WipeStrategy):
    """
    Wipe a Windows disk using DISKPART's `clean all` command.

    `clean all` writes zeros to every sector of the selected disk,
    removing all data and partition structures. This is slower than
    `clean` (which only removes partition table) but forensically sounder.

    IMPORTANT LIMITATION:
    `clean all` CANNOT be run on the disk containing the active Windows OS.
    Enterprise solution: Boot from WinPE / bootable ISO / PXE and run
    diskpart from there. See LIMITATIONS section in documentation.

    Commands (fed as script to diskpart):
        select disk N
        clean all
        exit
    """

    name = "Windows-DiskPart"
    description = "diskpart clean all (Windows disks)"

    def execute(self, disk, executor, log_callback=None) -> bool:
        disk_number = disk.identifier  # e.g. "1", "2"

        # Build diskpart script
        diskpart_script = (
            f"select disk {disk_number}\r\n"
            f"clean all\r\n"
            f"exit\r\n"
        )

        # Write script to temp file and execute
        script_path = f"C:\\WiperX_diskpart_{disk_number}.txt"
        write_cmd = (
            f'powershell -Command "Set-Content -Path \'{script_path}\' '
            f'-Value @\'\\n{diskpart_script}\\n\'@"'
        )
        run_cmd = f'diskpart /s "{script_path}"'
        cleanup_cmd = f'del /f "{script_path}"'

        self._log(f"Preparing diskpart script for Disk {disk_number}", log_callback)
        self._log(
            "WARNING: clean all will destroy ALL data. This cannot be undone.",
            log_callback
        )
        self._log(f"Diskpart script:\n{diskpart_script}", log_callback)

        try:
            # Write the script file
            self._log(f"Writing diskpart script to {script_path}", log_callback)
            executor.run_command(write_cmd)

            # Run diskpart
            self._log(f"Executing: {run_cmd}", log_callback)
            result = executor.run_command(run_cmd, timeout=14400)  # 4hr max
            self._log(f"diskpart output:\n{result}", log_callback)

            # Cleanup
            executor.run_command(cleanup_cmd)
            self._log(f"Windows wipe complete for Disk {disk_number}", log_callback)
            return True

        except Exception as e:
            self._log(
                f"ERROR: diskpart clean all failed for Disk {disk_number}: {e}",
                log_callback
            )
            return False


# ---------------------------------------------------------------------------
# Strategy Factory
# ---------------------------------------------------------------------------

def get_strategy(disk, os_type) -> WipeStrategy:
    """
    Factory function to select the appropriate wipe strategy
    based on disk properties and OS type.

    Args:
        disk    : DiskInfo object.
        os_type : OSType enum value.

    Returns:
        WipeStrategy: The appropriate strategy instance.

    Raises:
        ValueError: If no strategy matches the disk/OS combination.
    """
    from core.os_detector import OSType

    if os_type == OSType.WINDOWS:
        return WindowsWipeStrategy()

    if os_type == OSType.LINUX:
        if disk.bus_type == "USB":
            return LinuxUSBWipeStrategy()
        elif disk.disk_type == "NVMe" or "nvme" in disk.identifier.lower():
            return LinuxNVMeWipeStrategy()
        elif disk.disk_type == "SSD":
            return LinuxSSDWipeStrategy()
        else:
            return LinuxHDDWipeStrategy()  # Default to shred for HDD/unknown

    raise ValueError(
        f"No wipe strategy available for OS={os_type}, "
        f"disk_type={disk.disk_type}, bus_type={disk.bus_type}"
    )
