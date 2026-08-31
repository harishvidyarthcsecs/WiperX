# wiperx/core/verifier.py
"""
Wipe Verification Module
------------------------
Post-wipe verification to confirm data destruction.

Linux : read N chunks spread across the FULL device length and classify
        each with core.entropy.looks_wiped (zeroed / fixed-fill / low-entropy
        / random-or-live). The pass/fail rule depends on what the wipe method
        was expected to leave behind:
          expected="zeroed" : every sample must read zeroed / fixed-fill /
                              low-entropy.
          expected="random" : samples are expected to be high-entropy, which
                              a read cannot tell apart from residual data, so
                              the verdict is "inconclusive" (report-only).
          expected="any"    : treat like "zeroed" (native shred -z / dd zero).
Windows : partition table must be empty after `diskpart clean all`.

The result dict always carries `verified`, `method`, `details` for
report_generator compatibility, plus the richer entropy fields.
"""

from __future__ import annotations

import logging
import random
from typing import Callable, Optional

from core.entropy import looks_wiped

logger = logging.getLogger(__name__)


class WipeVerifier:
    """Verifies a disk wipe by sampling device content across its whole length."""

    SAMPLE_COUNT = 256          # chunks sampled across the device
    SAMPLE_SIZE = 4096          # bytes per chunk (8 x 512-byte sectors)

    def verify(
        self,
        disk,
        executor,
        os_type,
        log_callback: Optional[Callable[[str], None]] = None,
        *,
        sample_count: Optional[int] = None,
        expected: str = "any",
    ) -> dict:
        """
        Verify wipe success on a disk.

        Args:
            disk         : DiskInfo of the wiped disk.
            executor     : Executor to run verification commands.
            os_type      : OSType of the target.
            log_callback : Optional real-time log callback.
            sample_count : Chunks to sample (default SAMPLE_COUNT).
            expected     : "zeroed" | "random" | "any" — what the wipe method
                           should have left on the medium.

        Returns:
            dict: {verified, method, details, samples, nonzero, verdicts,
                   entropy_min, entropy_mean, entropy_max, coverage_pct}
        """
        from core.os_detector import OSType

        def _log(msg):
            logger.info(f"[Verifier] {msg}")
            if log_callback:
                log_callback(f"[Verifier] {msg}")

        _log(f"Starting post-wipe verification for disk: {disk.identifier} "
             f"(expected={expected})")

        if os_type == OSType.LINUX:
            return self._verify_linux(disk, executor, _log,
                                      sample_count or self.SAMPLE_COUNT, expected)
        if os_type == OSType.WINDOWS:
            return self._verify_windows(disk, executor, _log)
        return {
            "verified": False,
            "method": "none",
            "details": f"Verification not supported for OS: {os_type}",
        }

    # ------------------------------------------------------------------

    def _verify_linux(self, disk, executor, log_fn, sample_count, expected) -> dict:
        device_path = f"/dev/{disk.identifier}"
        size_bytes = getattr(disk, "size_bytes", 0) or 0
        max_offset = max(0, size_bytes - self.SAMPLE_SIZE)
        log_fn(f"Sampling {sample_count} x {self.SAMPLE_SIZE}B chunks across "
               f"{device_path} ({size_bytes} bytes)")

        offsets = sorted(random.randint(0, max_offset) for _ in range(sample_count)) \
            if max_offset > 0 else [0]

        verdict_counts: dict[str, int] = {}
        entropies: list[float] = []
        nonzero = 0
        read_errors = 0

        for offset in offsets:
            skip = offset // 512
            cmd = (
                f"dd if={device_path} bs=512 skip={skip} "
                f"count={self.SAMPLE_SIZE // 512} 2>/dev/null | od -An -v -tx1"
            )
            try:
                raw = executor.run_command(cmd, timeout=30)
            except Exception as exc:  # noqa: BLE001 - record and continue
                read_errors += 1
                log_fn(f"WARNING: could not read offset {offset}: {exc}")
                continue

            buf = self._hex_to_bytes(raw)
            if not buf:
                read_errors += 1
                continue
            if any(buf):
                nonzero += 1
            v = looks_wiped(buf)
            verdict_counts[v.verdict] = verdict_counts.get(v.verdict, 0) + 1
            entropies.append(v.entropy)

        sampled = len(entropies)
        e_min = min(entropies) if entropies else 0.0
        e_max = max(entropies) if entropies else 0.0
        e_mean = sum(entropies) / sampled if sampled else 0.0
        coverage_pct = (
            round(100.0 * sampled * self.SAMPLE_SIZE / size_bytes, 4)
            if size_bytes else 0.0
        )

        live = verdict_counts.get("random-or-live", 0)
        clean = verdict_counts.get("zeroed", 0) + verdict_counts.get("fixed-fill", 0) \
            + verdict_counts.get("low-entropy", 0)

        if expected == "random":
            verified = None
            note = ("final wipe pass is random; a high-entropy read cannot be "
                    "distinguished from residual data - trust the completion status")
        else:  # "zeroed" or "any"
            verified = sampled > 0 and live == 0 and read_errors == 0
            note = f"{clean}/{sampled} samples read as wiped, {live} look live"

        details = (
            f"expected={expected}; sampled={sampled}; nonzero={nonzero}; "
            f"read_errors={read_errors}; verdicts={verdict_counts}; "
            f"entropy min/mean/max={e_min:.2f}/{e_mean:.2f}/{e_max:.2f}; "
            f"coverage={coverage_pct}% - {note}"
        )
        state = "PASSED" if verified else "INCONCLUSIVE" if verified is None else "FAILED"
        log_fn(f"Verification: {state} ({details})")

        return {
            "verified": verified,
            "method": "entropy_sampling",
            "details": details,
            "samples": sampled,
            "nonzero": nonzero,
            "read_errors": read_errors,
            "verdicts": verdict_counts,
            "entropy_min": round(e_min, 4),
            "entropy_mean": round(e_mean, 4),
            "entropy_max": round(e_max, 4),
            "coverage_pct": coverage_pct,
            "expected": expected,
        }

    @staticmethod
    def _hex_to_bytes(od_output: str) -> bytes:
        """Parse `od -An -tx1` output into raw bytes."""
        tokens = str(od_output).split()
        out = bytearray()
        for tok in tokens:
            try:
                out.append(int(tok, 16))
            except ValueError:
                continue
        return bytes(out)

    # ------------------------------------------------------------------

    def _verify_windows(self, disk, executor, log_fn) -> dict:
        """Verify a Windows wipe by checking the partition table is empty."""
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
            log_fn(f"Verification WARNING: Disk {disk.identifier} still has {count} partition(s).")
            return {
                "verified": False,
                "method": "partition_check",
                "details": f"Disk {disk.identifier}: {count} partition(s) still present.",
            }
        except Exception as e:  # noqa: BLE001
            log_fn(f"Verification error: {e}")
            return {
                "verified": False,
                "method": "partition_check",
                "details": f"Verification error: {e}",
            }
