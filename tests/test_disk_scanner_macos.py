"""macOS disk scanning via mocked `diskutil` plist output (runs on any OS)."""

import plistlib

from core.disk_scanner import DiskScanner
from core.os_detector import OSType


def _plist(obj) -> str:
    return plistlib.dumps(obj).decode("utf-8")


class _FakeExec:
    """Answers the diskutil / mount commands the macOS scanner issues."""

    def __init__(self):
        self.list = _plist({"WholeDisks": ["disk0", "disk2"]})
        self.info = {
            "disk0": _plist({
                "Size": 500_000_000_000, "MediaName": "APPLE SSD",
                "SolidState": True, "BusProtocol": "PCI-Express",
                "DeviceIdentifier": "disk0",
            }),
            "disk2": _plist({
                "Size": 2_000_000_000_000, "MediaName": "External HDD",
                "SolidState": False, "BusProtocol": "USB",
                "DeviceIdentifier": "disk2",
            }),
        }
        self.root = _plist({"ParentWholeDisk": "disk0"})
        self.mount = "/dev/disk0s2 on / (apfs, local, journaled)\n"

    def run_command(self, cmd, timeout=None):
        if cmd == "diskutil list -plist":
            return self.list
        if cmd == "diskutil info -plist /":
            return self.root
        if cmd == "mount":
            return self.mount
        for ident, blob in self.info.items():
            if cmd == f"diskutil info -plist {ident}":
                return blob
        raise AssertionError(f"unexpected command: {cmd}")


def test_macos_scan_parses_whole_disks():
    disks = DiskScanner(_FakeExec(), OSType.DARWIN).scan()
    by_id = {d.identifier: d for d in disks}
    assert set(by_id) == {"disk0", "disk2"}

    d0 = by_id["disk0"]
    assert d0.disk_type == "NVMe"
    assert d0.is_system is True
    assert d0.is_mounted is True
    assert d0.size_bytes == 500_000_000_000

    d2 = by_id["disk2"]
    assert d2.bus_type == "USB"
    assert d2.disk_type == "HDD"
    assert d2.is_system is False
