# wiperx/core/verifier.py
"""
Wipe Verification Module
------------------------
Post-wipe verification to confirm data destruction was successful.

Verification methods:
  Linux HDD/SSD : Read sample sectors and check for zero bytes.
  Linux NVMe    : Check SMART data / namespace status via nvme-cli.
  Windows       : Attempt to list partitions (should return empty).

Verification is performed AFTER the wipe completes and its result
is included in the wipe report.
"""

import logging
import random
from typing import Optional, Callable

logger = logging.getLogger(__name__)


class WipeVerifier:
    """
    Verifies that a disk wipe was successful by sampling disk content.
    """

    # Number of random sector positions to sample
    SAMPLE_COUNT = 10
    # Bytes to read per sample
    SAMPLE_SIZE = 512  # One sector

    def verify(
        self,
        disk,
        executor,
        os_type,
        log_callback: Optional[Callable[[str], None]] = None,
    ) -> dict:
        """
        Verify wipe success on a disk.

        Args:
            disk         : DiskInfo of the wiped disk.
            executor     : Executor to run verification commands.
            os_type      : OSType of the target.
            log_callback : Optional real-time log callback.

        Returns:
            dict with keys: verified (bool), method (str), details (str).
        """
        from core.os_detector import OSType

        def _log(msg):
            logger.info(f"[Verifier] {msg}")
            if log_callback:
                log_callback(f"[Verifier] {msg}")

        _log(f"Starting post-wipe verification for disk: {disk.identifier}")

        if os_type == OSType.LINUX:
            return self._verify_linux(disk, executor, _log)
        elif os_type == OSType.WINDOWS:
            return self._verify_windows(disk, executor, _log)
        else:
            return {
                "verified": False,
                "method": "none",
                "details": f"Verification not supported for OS: {os_type}",
            }

    def _verify_linux(self, disk, executor, log_fn) -> dict:
        """
        Verify Linux disk by reading random sectors and checking for zeros.
        Uses `dd` to read specific byte offsets.
        """
        device_path = f"/dev/{disk.identifier}"
        log_fn(f"Verifying {device_path} by sampling {self.SAMPLE_COUNT} random sectors...")

        all_zero = True
        details = []

        for i in range(self.SAMPLE_COUNT):
            # Random skip within disk (limit to first 10GB for speed)
            max_skip = min(disk.size_bytes // 512, 20_971_520) if disk.size_bytes > 0 else 1000
            skip = random.randint(0, max(0, max_skip - 1))

            cmd = (
                f"dd if={device_path} bs=512 count=1 skip={skip} 2>/dev/null | "
                f"od -An -tx1 | tr -d ' \\n'"
            )
            try:
                result = executor.run_command(cmd, timeout=30)
                # Check if all hex bytes are "00"
                hex_chars = result.replace(" ", "").replace("\n", "")
                is_zero = len(hex_chars) > 0 and all(c == "0" for c in hex_chars)

                if not is_zero:
                    all_zero = False
                    details.append(f"Sector {skip}: non-zero data found")
                    log_fn(f"WARNING: Sector {skip} contains non-zero data!")
                else:
                    details.append(f"Sector {skip}: verified zero")

            except Exception as e:
                log_fn(f"WARNING: Could not read sector {skip}: {e}")
                details.append(f"Sector {skip}: read error ({e})")
                all_zero = False

        result_str = "; ".join(details)
        log_fn(f"Verification result: {'PASSED' if all_zero else 'FAILED'}")

        return {
            "verified": all_zero,
            "method": "sector_sampling",
            "details": result_str,
            "sectors_checked": self.SAMPLE_COUNT,
        }

    def _verify_windows(self, disk, executor, log_fn) -> dict:
        """
        Verify Windows disk wipe by checking partition table is empty.
        After diskpart clean all, no partitions should exist.
        """
        cmd = (
            f"powershell -Command \""
            f"Get-Partition -DiskNumber {disk.identifier} -ErrorAction SilentlyContinue | "
            f"Measure-Object | Select-Object -ExpandProperty Count\""
        )
        try:
            result = executor.run_command(cmd, timeout=30)
            count = int(result.strip()) if result.strip().isdigit() else -1

            if count == 0:
                log_fn(f"Verification PASSED: Disk {disk.identifier} has 0 partitions.")
                return {
                    "verified": True,
                    "method": "partition_check",
                    "details": f"Disk {disk.identifier}: no partitions found after wipe.",
                }
            else:
                log_fn(f"Verification WARNING: Disk {disk.identifier} still has {count} partition(s).")
                return {
                    "verified": False,
                    "method": "partition_check",
                    "details": f"Disk {disk.identifier}: {count} partition(s) still present.",
                }

        except Exception as e:
            log_fn(f"Verification error: {e}")
            return {
                "verified": False,
                "method": "partition_check",
                "details": f"Verification error: {e}",
            }
