"""get_strategy() picks the right class for every OS (mocked disks)."""

import pytest

from core.disk_scanner import DiskInfo
from core.os_detector import OSType
from core.strategies import (
    get_strategy,
    LinuxHDDWipeStrategy, LinuxSSDWipeStrategy, LinuxNVMeWipeStrategy,
    LinuxUSBWipeStrategy, WindowsWipeStrategy,
    MacHDDWipeStrategy, MacSSDWipeStrategy,
)


def _disk(**kw):
    base = dict(identifier="sda", disk_type="HDD", bus_type="SATA")
    base.update(kw)
    return DiskInfo(**base)


@pytest.mark.parametrize("disk,expect", [
    (_disk(disk_type="HDD", bus_type="SATA"), LinuxHDDWipeStrategy),
    (_disk(disk_type="SSD", bus_type="SATA"), LinuxSSDWipeStrategy),
    (_disk(identifier="nvme0n1", disk_type="NVMe", bus_type="NVMe"), LinuxNVMeWipeStrategy),
    (_disk(disk_type="SSD", bus_type="USB"), LinuxUSBWipeStrategy),
])
def test_linux_selection(disk, expect):
    assert isinstance(get_strategy(disk, OSType.LINUX), expect)


def test_windows_selection():
    assert isinstance(
        get_strategy(_disk(identifier="0", disk_type="HDD", bus_type="RAID"),
                     OSType.WINDOWS),
        WindowsWipeStrategy,
    )


@pytest.mark.parametrize("disk,expect", [
    (_disk(identifier="disk0", disk_type="SSD", bus_type="PCIe"), MacSSDWipeStrategy),
    (_disk(identifier="disk3", disk_type="NVMe", bus_type="NVMe"), MacSSDWipeStrategy),
    (_disk(identifier="disk4", disk_type="SSD", bus_type="USB"), MacHDDWipeStrategy),
    (_disk(identifier="disk5", disk_type="HDD", bus_type="USB"), MacHDDWipeStrategy),
])
def test_macos_selection(disk, expect):
    assert isinstance(get_strategy(disk, OSType.DARWIN), expect)


def test_unsupported_raises():
    with pytest.raises(ValueError):
        get_strategy(_disk(), OSType.UNSUPPORTED)


def test_macos_secure_erase_level_from_pass_count():
    class _P:
        kind = "random"

    s = MacHDDWipeStrategy()
    assert s._level(None) == "0"
    assert s._level([_P()]) == "1"
    assert s._level([_P(), _P(), _P()]) == "4"
    assert s._level([_P()] * 7) == "2"
    assert s._level([_P()] * 35) == "3"
