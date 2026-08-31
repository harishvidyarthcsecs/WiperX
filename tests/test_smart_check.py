"""Tests for core.smart_check (advisory SMART pre-wipe health check)."""

from unittest.mock import MagicMock

from core.smart_check import check_health

_PASSED_OUTPUT = """\
smartctl 7.4 2023-08-01 r5530 [x86_64-linux-6.1.0] (local build)
=== START OF READ SMART DATA SECTION ===
SMART overall-health self-assessment test result: PASSED

ID# ATTRIBUTE_NAME          FLAG     VALUE WORST THRESH TYPE      UPDATED  WHEN_FAILED RAW_VALUE
  5 Reallocated_Sector_Ct   0x0033   100   100   005    Pre-fail  Always       -       0
194 Temperature_Celsius     0x0022   067   051   000    Old_age   Always       -       33
"""

_FAILED_OUTPUT = """\
smartctl 7.4 2023-08-01 r5530 [x86_64-linux-6.1.0] (local build)
=== START OF READ SMART DATA SECTION ===
SMART overall-health self-assessment test result: FAILED!

ID# ATTRIBUTE_NAME          FLAG     VALUE WORST THRESH TYPE      UPDATED  WHEN_FAILED RAW_VALUE
  5 Reallocated_Sector_Ct   0x0033   050   050   005    Pre-fail  Always   FAILING_NOW    212
"""


def _executor(stdout=None, exc=None):
    executor = MagicMock()
    if exc is not None:
        executor.run_command.side_effect = exc
    else:
        executor.run_command.return_value = stdout
    return executor


def test_healthy_drive_reports_passed():
    result = check_health("/dev/sda", _executor(_PASSED_OUTPUT))
    assert result["available"] is True
    assert result["healthy"] is True
    assert "PASSED" in result["detail"]
    assert result["temperature_c"] == 33
    assert result["reallocated_sectors"] == 0


def test_failing_drive_reports_failed():
    result = check_health("/dev/sda", _executor(_FAILED_OUTPUT))
    assert result["available"] is True
    assert result["healthy"] is False
    assert "FAILED" in result["detail"]
    assert result["reallocated_sectors"] == 212


def test_smartctl_missing_is_advisory_not_fatal():
    result = check_health("/dev/sda", _executor(exc=RuntimeError("smartctl: not found")))
    assert result["available"] is False
    assert result["healthy"] is None
    assert "unavailable" in result["detail"]


def test_unparseable_output_is_inconclusive_not_a_crash():
    result = check_health("/dev/sda", _executor("garbage output, no SMART section"))
    assert result["available"] is True
    assert result["healthy"] is None


def test_log_callback_receives_lines():
    lines = []
    check_health("/dev/sda", _executor(_PASSED_OUTPUT), log_callback=lines.append)
    assert any("PASSED" in line for line in lines)
