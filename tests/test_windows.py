"""Windows disk detection: is_system / is_mounted derivation via
Get-Disk + Get-Partition (ENG-04, ENG-05).

All tests drive the real _scan_windows code path through a fake executor -
no PowerShell or real devices are touched. No live Windows box is available
in this environment; these are code-review-verified + unit-tested only.
"""

from core.disk_scanner import DiskScanner
from core.os_detector import OSType


class FakeExecutor:
    """Executor stub: dispatch on command substring, record every call."""

    def __init__(self, responses=None, errors=None):
        self.responses = responses or {}
        self.errors = errors or {}
        self.calls = []

    def run_command(self, command, timeout=120):
        self.calls.append(command)
        for needle, exc in self.errors.items():
            if needle in command:
                raise RuntimeError(exc)
        for needle, out in self.responses.items():
            if needle in command:
                return out
        return ""


def _get_disk_csv(rows):
    """rows: list of (Number, Model, SerialNumber, Size, BusType, OperationalStatus)."""
    header = "Number,Model,SerialNumber,Size,BusType,OperationalStatus"
    lines = [header]
    for r in rows:
        lines.append(",".join(str(v) for v in r))
    return "\r\n".join(lines) + "\r\n"


def _system_disk_csv(disk_number):
    return f"DiskNumber\r\n{disk_number}\r\n"


def _partitions_csv(rows):
    """rows: list of (DiskNumber, DriveLetter)."""
    lines = ["DiskNumber,DriveLetter"]
    for disk_number, letter in rows:
        lines.append(f"{disk_number},{letter}")
    return "\r\n".join(lines) + "\r\n"


def test_non_system_disk_with_mounted_volume_is_flagged_mounted():
    """ENG-04 regression: a non-system disk with an actual mounted volume
    must report is_mounted=True, not the old "always False unless disk 0"
    behaviour."""
    ex = FakeExecutor(responses={
        DiskScanner.WINDOWS_GET_DISK_CMD: _get_disk_csv([
            ("0", "System Disk", "SN0", "256000000000", "SATA", "Healthy"),
            ("1", "Data Disk", "SN1", "1000000000000", "SATA", "Healthy"),
        ]),
        DiskScanner.WINDOWS_GET_SYSTEM_DISK_CMD: _system_disk_csv("0"),
        DiskScanner.WINDOWS_GET_PARTITIONS_CMD: _partitions_csv([
            ("0", "C"),
            ("1", "D"),
        ]),
    })
    disks = DiskScanner(executor=ex, os_type=OSType.WINDOWS).scan()

    by_number = {d.identifier: d for d in disks}
    assert by_number["0"].is_system is True
    assert by_number["0"].is_mounted is True
    assert by_number["1"].is_system is False
    assert by_number["1"].is_mounted is True  # ENG-04: previously always False


def test_system_disk_not_numbered_zero_is_detected_correctly():
    """ENG-05 regression: on a box where Windows is on disk 1 (not 0), disk 1
    must be flagged is_system=True and disk 0 must not."""
    ex = FakeExecutor(responses={
        DiskScanner.WINDOWS_GET_DISK_CMD: _get_disk_csv([
            ("0", "Data Disk", "SN0", "1000000000000", "SATA", "Healthy"),
            ("1", "Boot Disk", "SN1", "256000000000", "NVMe", "Healthy"),
        ]),
        DiskScanner.WINDOWS_GET_SYSTEM_DISK_CMD: _system_disk_csv("1"),
        DiskScanner.WINDOWS_GET_PARTITIONS_CMD: _partitions_csv([
            ("0", ""),
            ("1", "C"),
        ]),
    })
    disks = DiskScanner(executor=ex, os_type=OSType.WINDOWS).scan()

    by_number = {d.identifier: d for d in disks}
    assert by_number["1"].is_system is True
    assert by_number["0"].is_system is False
    assert by_number["0"].is_mounted is False  # no drive letter assigned


def test_system_disk_query_failure_marks_every_disk_unknown():
    ex = FakeExecutor(
        responses={
            DiskScanner.WINDOWS_GET_DISK_CMD: _get_disk_csv([
                ("0", "Disk", "SN0", "256000000000", "SATA", "Healthy"),
            ]),
            DiskScanner.WINDOWS_GET_PARTITIONS_CMD: _partitions_csv([("0", "C")]),
        },
        errors={DiskScanner.WINDOWS_GET_SYSTEM_DISK_CMD: "PowerShell not found"},
    )
    disks = DiskScanner(executor=ex, os_type=OSType.WINDOWS).scan()

    assert len(disks) == 1
    assert disks[0].is_system is None
    assert disks[0].is_mounted is None


def test_partitions_query_failure_marks_every_disk_unknown():
    ex = FakeExecutor(
        responses={
            DiskScanner.WINDOWS_GET_DISK_CMD: _get_disk_csv([
                ("0", "Disk", "SN0", "256000000000", "SATA", "Healthy"),
            ]),
            DiskScanner.WINDOWS_GET_SYSTEM_DISK_CMD: _system_disk_csv("0"),
        },
        errors={DiskScanner.WINDOWS_GET_PARTITIONS_CMD: "PowerShell not found"},
    )
    disks = DiskScanner(executor=ex, os_type=OSType.WINDOWS).scan()

    assert len(disks) == 1
    assert disks[0].is_system is None
    assert disks[0].is_mounted is None
