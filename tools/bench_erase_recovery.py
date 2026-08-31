#!/usr/bin/env python3
# wiperx/tools/bench_erase_recovery.py
"""
Performance benchmark harness for Module 2 (Secure File & Folder Eraser)
and Module 3 (Advanced File Carving & Recovery).

Runs entirely on regular files / file-based images owned by the current
user - no root, no loop devices, no mounting. Prints JSON to stdout so
the numbers can be pasted straight into docs/PERFORMANCE_EVALUATION.md.

Module 1 (real /dev/* wipe strategies) is NOT covered here - that needs
root (core.execution_manager._check_privileges is unconditional) and is
documented as a fill-in-the-numbers methodology instead.

Usage:
    .venv/bin/python tools/bench_erase_recovery.py
"""
from __future__ import annotations

import json
import os
import shutil
import subprocess
import sys
import tempfile
import time
from pathlib import Path

ROOT = Path(__file__).parent.parent
sys.path.insert(0, str(ROOT))

from core.eraser_file.service import erase_paths          # noqa: E402
from core.recovery.carver_fragment import carve_bifragment_jpeg  # noqa: E402
from core.recovery.service import recover                 # noqa: E402


def _mb(n_bytes: int) -> float:
    return n_bytes / (1024 * 1024)


# ---------------------------------------------------------------------------
# Module 2 - Secure File & Folder Eraser: real shred throughput
# ---------------------------------------------------------------------------

def bench_eraser() -> list[dict]:
    results = []
    sizes_mb = [1, 10, 100]
    pass_counts = [1, 3, 7]
    with tempfile.TemporaryDirectory(prefix="wiperx_bench_erase_") as tmp:
        tmp = Path(tmp)
        for size_mb in sizes_mb:
            for passes in pass_counts:
                f = tmp / f"sample_{size_mb}mb_{passes}p.bin"
                with open(f, "wb") as fh:
                    fh.write(os.urandom(size_mb * 1024 * 1024))
                start = time.perf_counter()
                report = erase_paths(
                    [str(f)],
                    recursive=False,
                    passes=passes,
                    zero_final=True,
                    workers=1,
                    operator="bench",
                    reports_dir=tmp,
                )
                elapsed = time.perf_counter() - start
                mb_per_s = size_mb / elapsed if elapsed > 0 else float("inf")
                results.append({
                    "size_mb": size_mb,
                    "passes": passes,
                    "elapsed_s": round(elapsed, 4),
                    "throughput_mb_s": round(mb_per_s, 2),
                    "file_still_exists": f.exists(),
                    "certificate_signed": report.get("certificate_signed"),
                })
    return results


# ---------------------------------------------------------------------------
# Module 3a - carving accuracy on synthetic JPEGs (real PIL-encoded images,
# same technique as tests/test_carver_fragment.py)
# ---------------------------------------------------------------------------

def _noisy_jpeg(rng, side: int = 160, quality: int = 88) -> bytes:
    import io
    from PIL import Image
    img = Image.frombytes("RGB", (side, side), rng.randbytes(side * side * 3))
    buf = io.BytesIO()
    img.save(buf, "JPEG", quality=quality)
    return buf.getvalue()


def bench_carving_synthetic() -> dict:
    import random
    try:
        import PIL  # noqa: F401
    except ImportError:
        return {"skipped": True, "reason": "Pillow not installed"}

    rng = random.Random(42)
    trials = 50
    block = 512

    contiguous_ok = 0
    bifrag_ok = 0
    false_positives = 0
    timings_s = []

    for _ in range(trials):
        jpg = _noisy_jpeg(rng)
        region = jpg + b"\x00" * 4000
        t0 = time.perf_counter()
        res = carve_bifragment_jpeg(region, block_size=block)
        timings_s.append(time.perf_counter() - t0)
        if res.validated and res.recovered == jpg:
            contiguous_ok += 1

    for gap_blocks in (1, 3, 8):
        for _ in range(trials // 3 or 1):
            jpg = _noisy_jpeg(rng)
            cut = ((len(jpg) // 2) // block) * block
            region = jpg[:cut] + rng.randbytes(block * gap_blocks) + jpg[cut:] + b"\xab" * 2000
            t0 = time.perf_counter()
            res = carve_bifragment_jpeg(region, block_size=block)
            timings_s.append(time.perf_counter() - t0)
            if res.validated and res.recovered == jpg:
                bifrag_ok += 1

    bifrag_trials = 3 * (trials // 3 or 1)

    for _ in range(trials):
        garbage = rng.randbytes(3000)
        res = carve_bifragment_jpeg(garbage)
        if res.recovered is not None:
            false_positives += 1

    return {
        "contiguous_trials": trials,
        "contiguous_recovery_rate": round(contiguous_ok / trials, 4),
        "bifragment_trials": bifrag_trials,
        "bifragment_recovery_rate": round(bifrag_ok / bifrag_trials, 4),
        "false_positive_trials": trials,
        "false_positive_rate_on_garbage": round(false_positives / trials, 4),
        "avg_carve_time_ms": round(1000 * sum(timings_s) / len(timings_s), 3),
    }


# ---------------------------------------------------------------------------
# Module 3b - end-to-end recovery against a real, populated ext4 image
# (mkfs.ext4 -d populates from a directory; debugfs -w deletes; both work
#  on a plain regular file with no root and no mount.)
# ---------------------------------------------------------------------------

def bench_recovery_e2e() -> dict:
    with tempfile.TemporaryDirectory(prefix="wiperx_bench_recover_") as tmp:
        tmp = Path(tmp)
        seed = tmp / "seed"
        seed.mkdir()
        marker = b"WIPERX-BENCH-MARKER-2026"
        planted = {
            "notes.txt": b"case notes\n" + marker + b"\nend\n",
            "report.txt": (b"lorem ipsum " * 200) + marker,
        }
        for name, data in planted.items():
            (seed / name).write_bytes(data)

        image = tmp / "bench.img"
        size_mb = 32
        subprocess.run(
            ["dd", "if=/dev/zero", f"of={image}", "bs=1M", f"count={size_mb}", "status=none"],
            check=True,
        )
        mkfs = subprocess.run(
            ["mkfs.ext4", "-q", "-F", "-d", str(seed), str(image)],
            capture_output=True, text=True,
        )
        if mkfs.returncode != 0:
            return {"error": "mkfs.ext4 failed", "stderr": mkfs.stderr, "skipped": True}

        # Delete one seed file from inside the image without mounting it.
        rm = subprocess.run(
            ["debugfs", "-w", "-R", "rm /notes.txt", str(image)],
            capture_output=True, text=True,
        )
        if rm.returncode != 0:
            return {"error": "debugfs rm failed", "stderr": rm.stderr, "skipped": True}

        case_dir = tmp / "case"
        start = time.perf_counter()
        result = recover(
            source_path=str(image),
            out_dir=str(case_dir),
            operator="bench",
        )
        elapsed = time.perf_counter() - start

        records = result.get("records", [])
        marker_hits = 0
        for r in records:
            p = Path(result["case_dir"]) / r["recovered_path"]
            if p.exists() and marker in p.read_bytes():
                marker_hits += 1

        return {
            "image_size_mb": size_mb,
            "elapsed_s": round(elapsed, 4),
            "throughput_mb_s": round(size_mb / elapsed, 2) if elapsed > 0 else None,
            "files_recovered": len(records),
            "files_with_marker_intact": marker_hits,
            "confidence_scores": [r.get("confidence_score") for r in records],
            "confidence_bands": [r.get("confidence_band") for r in records],
            "case_report_signed": result.get("signed"),
            "summary": result.get("summary"),
        }


if __name__ == "__main__":
    out = {
        "module2_eraser_throughput": bench_eraser(),
        "module3a_carving_synthetic": bench_carving_synthetic(),
        "module3b_recovery_e2e": bench_recovery_e2e(),
    }
    print(json.dumps(out, indent=2, default=str))
