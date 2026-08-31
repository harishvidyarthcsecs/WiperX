# wiperx/core/smart_check.py
"""
SMART Health Pre-Check
-----------------------
Advisory disk-health check via `smartctl -H` (smartmontools), run before a
wipe so an operator can see "this drive is already failing" before spending
time overwriting it. This is deliberately advisory-only and never blocks a
wipe — smartctl commonly needs root, may not be installed, and some
USB/NVMe bridges don't pass SMART commands through reliably. A missing or
inconclusive result is reported as such, not treated as a failure.
"""

from __future__ import annotations

import logging
import re

logger = logging.getLogger(__name__)

_OVERALL_RE = re.compile(r"SMART overall-health self-assessment test result:\s*(\w+)", re.I)
# smartctl -A prints one attribute per line, ending in its RAW_VALUE, e.g.:
#   194 Temperature_Celsius     0x0022   067   051   000  Old_age Always   -   33
#     5 Reallocated_Sector_Ct   0x0033   100   100   005  Pre-fail Always  -   0
_TEMP_RE = re.compile(r"Temperature_Celsius.*\s(\d+)\s*$", re.I | re.M)
_REALLOC_RE = re.compile(r"Reallocated_Sector_Ct.*\s(\d+)\s*$", re.I | re.M)


def check_health(device_path: str, executor, log_callback=None) -> dict:
    """
    Advisory pre-wipe SMART health check.

    Args:
        device_path  : e.g. /dev/sdb.
        executor     : command executor (local/SSH/WinRM - anything exposing
                       run_command(cmd, timeout=...)).
        log_callback : optional real-time log sink.

    Returns:
        dict: {
            "available"  : bool  - smartctl ran and returned SMART data,
            "healthy"    : True | False | None (None = unknown/inconclusive),
            "detail"     : short human-readable summary,
            "temperature_c": int | None,
            "reallocated_sectors": int | None,
            "raw"        : full smartctl -H -A output, or "" if unavailable,
        }
    """
    def _log(msg: str) -> None:
        logger.info("[smart_check] %s", msg)
        if log_callback:
            log_callback(f"[smart_check] {msg}")

    result = {
        "available": False,
        "healthy": None,
        "detail": "smartctl not run",
        "temperature_c": None,
        "reallocated_sectors": None,
        "raw": "",
    }

    try:
        out = str(executor.run_command(f"smartctl -H -A {device_path}", timeout=30))
    except Exception as exc:  # noqa: BLE001 - advisory only, never fatal
        _log(f"smartctl unavailable or failed on {device_path}: {exc}")
        result["detail"] = f"smartctl unavailable: {exc}"
        return result

    result["raw"] = out
    result["available"] = True

    m = _OVERALL_RE.search(out)
    if m:
        verdict = m.group(1).strip().upper()
        if verdict == "PASSED":
            result["healthy"] = True
            result["detail"] = "SMART overall-health: PASSED"
        elif verdict == "FAILED":
            result["healthy"] = False
            result["detail"] = "SMART overall-health: FAILED — drive reports imminent failure"
        else:
            result["detail"] = f"SMART overall-health: {verdict} (unrecognized verdict)"
    else:
        result["detail"] = "smartctl ran but no overall-health line found (unsupported device?)"

    temp_m = _TEMP_RE.search(out)
    if temp_m:
        result["temperature_c"] = int(temp_m.group(1))

    realloc_m = _REALLOC_RE.search(out)
    if realloc_m:
        result["reallocated_sectors"] = int(realloc_m.group(1))
        if result["reallocated_sectors"] > 0 and result["healthy"] is not False:
            _log(
                f"{result['reallocated_sectors']} reallocated sector(s) on "
                f"{device_path} — drive is degrading even though overall-health "
                "may still say PASSED."
            )

    _log(f"{device_path}: {result['detail']}")
    return result
