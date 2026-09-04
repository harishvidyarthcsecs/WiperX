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
  - MacOSWipeStrategy     : diskutil secureErase / dd to /dev/rdiskN

Each strategy implements the WipeStrategy base class with a
single `execute(disk, executor, log_callback)` method.
"""

import logging
import shlex
from abc import ABC, abstractmethod
from typing import Callable, List, Optional

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
        passes: Optional[List] = None,
    ) -> bool:
        """
        Execute the wipe strategy on the given disk.

        Args:
            disk         : DiskInfo object describing the target disk.
            executor     : Executor instance to run commands.
            log_callback : Optional callable to receive real-time log lines.
            passes       : Optional list of core.wipe_passes.PassSpec. When
                           given, the overwrite strategies run exactly this
                           sequence of device-wide passes instead of their
                           native single-shot command. None = native default.

        Returns:
            bool: True if wipe succeeded, False otherwise.
        """
        pass

    def _log(self, message: str, log_callback: Optional[Callable] = None):
        """Helper to log both to logger and optional callback."""
        logger.info(f"[{self.name}] {message}")
        if log_callback:
            log_callback(f"[{self.name}] {message}")

    def _run_passes(self, device_path, executor, passes, log_callback=None) -> bool:
        """
        Run an explicit list of PassSpec overwrites across a whole block device.

        Each pass is one `dd` sweep:
          random     -> dd if=/dev/urandom
          fixed 0x00 -> dd if=/dev/zero
          fixed 0xNN -> tr '\\0' '\\NNN' < /dev/zero | dd
          verify     -> skipped here (handled by the post-wipe verifier)

        Args:
            device_path  : e.g. /dev/sdb.
            executor     : command executor.
            passes       : list of core.wipe_passes.PassSpec.
            log_callback : optional real-time log sink.

        Returns:
            bool: True if every write pass completed (ENOSPC on an unbounded
            fill counts as success — the device is full).
        """
        quoted = shlex.quote(device_path)
        bs_mib = 4
        count_clause = ""
        try:
            size_out = executor.run_command(f"blockdev --getsize64 {quoted}", timeout=30)
            total_bytes = int(str(size_out).strip().split()[0])
            if total_bytes > 0:
                unit = bs_mib * 1024 * 1024
                blocks = (total_bytes + unit - 1) // unit
                count_clause = f" count={blocks}"
        except Exception as exc:  # noqa: BLE001 - size is an optimisation, not required
            self._log(f"Could not read device size ({exc}); writing unbounded.", log_callback)

        total = len(passes)
        for index, spec in enumerate(passes, start=1):
            kind = getattr(spec, "kind", "random")
            byte = getattr(spec, "byte", None)

            if kind == "verify":
                self._log(
                    f"Pass {index}/{total}: verify pass - deferred to post-wipe verifier",
                    log_callback,
                )
                continue

            if kind == "random":
                cmd = (
                    f"dd if=/dev/urandom of={quoted} bs={bs_mib}M{count_clause} "
                    f"conv=fsync iflag=fullblock status=none"
                )
                label = "random"
            elif byte == 0:
                cmd = (
                    f"dd if=/dev/zero of={quoted} bs={bs_mib}M{count_clause} "
                    f"conv=fsync status=none"
                )
                label = "0x00"
            else:
                octal = format(int(byte), "03o")
                cmd = (
                    f"tr '\\0' '\\{octal}' < /dev/zero | "
                    f"dd of={quoted} bs={bs_mib}M{count_clause} "
                    f"conv=fsync iflag=fullblock status=none"
                )
                label = f"0x{int(byte):02x}"

            self._log(f"Pass {index}/{total} ({label}): {cmd}", log_callback)
            try:
                out = executor.run_command(cmd, timeout=14400)
                self._log(
                    f"Pass {index}/{total} ({label}) complete. {str(out).strip()[:200]}",
                    log_callback,
                )
            except Exception as exc:  # noqa: BLE001 - inspect and decide
                if "No space left on device" in str(exc):
                    self._log(
                        f"Pass {index}/{total} ({label}) filled the device "
                        "(ENOSPC on unbounded fill = expected).",
                        log_callback,
                    )
                    continue
                self._log(f"ERROR: pass {index}/{total} ({label}) failed: {exc}", log_callback)
                return False

        self._log(f"All {total} pass(es) complete on {device_path}", log_callback)
        return True


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

    def execute(self, disk, executor, log_callback=None, passes=None) -> bool:
        device_path = f"/dev/{disk.identifier}"

        if passes:
            self._log(
                f"Multi-pass overwrite ({len(passes)} pass(es)) on {device_path}",
                log_callback,
            )
            return self._run_passes(device_path, executor, passes, log_callback)

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

    def execute(self, disk, executor, log_callback=None, passes=None) -> bool:
        device_path = f"/dev/{disk.identifier}"

        # Step 1: blkdiscard (TRIM hint — always, harmless if unsupported)
        cmd_discard = f"blkdiscard {device_path}"
        self._log(f"Step 1: blkdiscard on {device_path}", log_callback)
        self._log(f"Command: {cmd_discard}", log_callback)
        try:
            out = executor.run_command(cmd_discard, timeout=600)
            self._log(f"blkdiscard output: {out}", log_callback)
        except Exception as e:
            self._log(f"WARNING: blkdiscard failed (non-fatal): {e}", log_callback)
            # blkdiscard may not be supported on all SSDs; continue to overwrite

        # Step 2: overwrite pass(es)
        if passes:
            self._log(
                f"Step 2: multi-pass overwrite ({len(passes)} pass(es)) on {device_path}",
                log_callback,
            )
            return self._run_passes(device_path, executor, passes, log_callback)

        cmd_dd = f"dd if=/dev/zero of={device_path} bs=4M status=progress conv=fsync"
        self._log(f"Step 2: dd zero pass on {device_path}", log_callback)
        self._log(f"Command: {cmd_dd}", log_callback)
        try:
            out = executor.run_command(cmd_dd, timeout=7200)
            self._log(f"dd output: {out}", log_callback)
            self._log(f"Wipe complete on {device_path}", log_callback)
            return True
        except Exception as e:
            self._log(f"ERROR: dd zero pass failed: {e}", log_callback)
            return False


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

    def execute(self, disk, executor, log_callback=None, passes=None) -> bool:
        if passes and len(passes) > 1:
            self._log(
                f"NOTE: 'nvme format --ses=1' is a single-shot controller "
                f"cryptographic erase; the requested {len(passes)}-pass overwrite "
                "pattern does not apply and is recorded for the report only.",
                log_callback,
            )

        # NVMe device paths: /dev/nvme0n1, /dev/nvme1n1, etc.
        # The identifier may be "nvme0n1" or "nvme0" — normalize it
        identifier = disk.identifier
        if not identifier.startswith("nvme"):
            identifier = "nvme0n1"  # fallback

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

    def execute(self, disk, executor, log_callback=None, passes=None) -> bool:
        device_path = f"/dev/{disk.identifier}"

        if passes:
            self._log(
                f"Multi-pass overwrite ({len(passes)} pass(es)) on {device_path}",
                log_callback,
            )
            return self._run_passes(device_path, executor, passes, log_callback)

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

    def execute(self, disk, executor, log_callback=None, passes=None) -> bool:
        disk_number = disk.identifier  # e.g. "1", "2"

        if passes and len(passes) > 1:
            self._log(
                f"NOTE: 'diskpart clean all' writes zeros to every sector in one "
                f"operation; the requested {len(passes)}-pass pattern does not apply "
                "and is recorded for the report only.",
                log_callback,
            )

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
# macOS Wipe Strategy — diskutil secureErase / dd to raw device
# ---------------------------------------------------------------------------

class MacOSWipeStrategy(WipeStrategy):
    """
    Wipe an external macOS disk.

    Native (no --method / passes):
        diskutil unmountDisk force /dev/diskX
        diskutil secureErase 0 diskX          (single-pass zero fill)

    Multi-pass (--method dod/gutmann/... -> passes list):
        diskutil unmountDisk force /dev/diskX
        dd if=/dev/urandom|/dev/zero of=/dev/rdiskX bs=1m count=<size>

    LIMITATIONS:
      - The disk holding the running OS cannot be wiped (refused here).
      - Apple-silicon internal storage ("Apple Fabric") is not addressable for
        an overwrite; use Erase All Content and Settings (hardware crypto-erase).
        Such a target is refused here.
    """

    name = "macOS-diskutil"
    description = "diskutil secureErase / dd raw-device overwrite (external disks)"

    def execute(self, disk, executor, log_callback=None, passes=None) -> bool:
        ident = disk.identifier
        whole = f"/dev/{ident}"
        raw = f"/dev/r{ident}"

        if getattr(disk, "is_system", False):
            self._log(
                f"REFUSED: {ident} backs the running macOS install and cannot "
                "be wiped from a live system. Boot from a second volume / "
                "Recovery and wipe from there.",
                log_callback,
            )
            return False

        if disk.bus_type == "Apple Fabric" or (
            disk.disk_type == "NVMe" and getattr(disk, "bus_type", "") == "Apple Fabric"
        ):
            self._log(
                f"REFUSED: {ident} is Apple-silicon internal storage. It is not "
                "addressable for a sector overwrite; use 'Erase All Content and "
                "Settings' (hardware cryptographic erase).",
                log_callback,
            )
            return False

        # Unmount so writes are not blocked. For a single partition unmount just
        # that slice; for a whole disk unmount the whole disk.
        is_part = getattr(disk, "is_partition", False)
        umount_cmd = (
            f"diskutil unmount force {whole}" if is_part
            else f"diskutil unmountDisk force {whole}"
        )
        try:
            out = executor.run_command(umount_cmd, timeout=120)
            self._log(f"unmount: {str(out).strip()}", log_callback)
        except Exception as e:  # noqa: BLE001 - continue; secureErase also unmounts
            self._log(f"WARNING: unmount failed (non-fatal): {e}", log_callback)

        if passes:
            self._log(
                f"Multi-pass overwrite ({len(passes)} pass(es)) on {raw}",
                log_callback,
            )
            ok = self._run_passes_macos(raw, disk, executor, passes, log_callback)
            try:
                executor.run_command("sync", timeout=60)
            except Exception:  # noqa: BLE001
                pass
            return ok

        cmd = f"diskutil secureErase 0 {ident}"
        self._log(f"Starting single-pass zero erase on {ident}", log_callback)
        self._log(f"Command: {cmd}", log_callback)
        try:
            result = executor.run_command(cmd, timeout=14400)
            self._log(f"secureErase output: {str(result).strip()}", log_callback)
            self._log(f"Wipe complete on {ident}", log_callback)
            return True
        except Exception as e:
            self._log(
                f"ERROR: 'diskutil secureErase' failed on {ident}: {e}. "
                "Some SSDs refuse secureErase; retry with an explicit "
                "--method (multi-pass dd) or wipe from Recovery.",
                log_callback,
            )
            return False

    def _run_passes_macos(self, raw_device, disk, executor, passes, log_callback=None) -> bool:
        """Explicit PassSpec overwrites via BSD dd against a raw device node."""
        quoted = shlex.quote(raw_device)
        bs_mib = 1
        count_clause = ""
        size_bytes = int(getattr(disk, "size_bytes", 0) or 0)
        if size_bytes > 0:
            unit = bs_mib * 1024 * 1024
            blocks = (size_bytes + unit - 1) // unit
            count_clause = f" count={blocks}"
        else:
            self._log("Device size unknown; writing until ENOSPC.", log_callback)

        total = len(passes)
        for index, spec in enumerate(passes, start=1):
            kind = getattr(spec, "kind", "random")
            byte = getattr(spec, "byte", None)

            if kind == "verify":
                self._log(
                    f"Pass {index}/{total}: verify pass - deferred to post-wipe verifier",
                    log_callback,
                )
                continue

            if kind == "random":
                cmd = f"dd if=/dev/urandom of={quoted} bs={bs_mib}m{count_clause}"
                label = "random"
            elif byte == 0:
                cmd = f"dd if=/dev/zero of={quoted} bs={bs_mib}m{count_clause}"
                label = "0x00"
            else:
                octal = format(int(byte), "03o")
                cmd = (
                    f"LC_ALL=C tr '\\000' '\\{octal}' < /dev/zero | "
                    f"dd of={quoted} bs={bs_mib}m{count_clause}"
                )
                label = f"0x{int(byte):02x}"

            self._log(f"Pass {index}/{total} ({label}): {cmd}", log_callback)
            try:
                out = executor.run_command(cmd, timeout=14400)
                self._log(
                    f"Pass {index}/{total} ({label}) complete. {str(out).strip()[:200]}",
                    log_callback,
                )
            except Exception as exc:  # noqa: BLE001
                if "No space left on device" in str(exc):
                    self._log(
                        f"Pass {index}/{total} ({label}) filled the device "
                        "(ENOSPC on unbounded fill = expected).",
                        log_callback,
                    )
                    continue
                self._log(f"ERROR: pass {index}/{total} ({label}) failed: {exc}", log_callback)
                return False

        self._log(f"All {total} pass(es) complete on {raw_device}", log_callback)
        return True


# ---------------------------------------------------------------------------
# Strategy Factory
# ---------------------------------------------------------------------------

def get_strategy(disk, os_type, method: str = "auto") -> WipeStrategy:
    """
    Factory function to select the appropriate wipe strategy
    based on disk properties and OS type.

    Args:
        disk    : DiskInfo object.
        os_type : OSType enum value.
        method  : Requested wipe method name (see core.wipe_passes). Reserved
                  for method-specific strategy routing (e.g. a future hdparm
                  ATA Secure Erase strategy); the overwrite pass list itself is
                  built by the caller and handed to ``execute(passes=...)``.

    Returns:
        WipeStrategy: The appropriate strategy instance.

    Raises:
        ValueError: If no strategy matches the disk/OS combination.
    """
    from core.os_detector import OSType

    if os_type == OSType.WINDOWS:
        return WindowsWipeStrategy()

    if os_type == OSType.MACOS:
        return MacOSWipeStrategy()

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
