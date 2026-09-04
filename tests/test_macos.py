"""macOS (Darwin) support: OS detection, disk scan, wipe strategy, verification.

All tests drive the real code paths through a fake executor — no `diskutil`,
`dd` or real devices are touched.
"""

import plistlib
from types import SimpleNamespace

import pytest

from core.os_detector import OSDetector, OSType


# ---------------------------------------------------------------------------
# Fakes
# ---------------------------------------------------------------------------

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


def _plist(obj) -> str:
    return plistlib.dumps(obj).decode()


# ---------------------------------------------------------------------------
# OS detection
# ---------------------------------------------------------------------------

def test_detect_remote_darwin_is_macos():
    ssh = FakeExecutor(responses={"uname -s": "Darwin\n"})
    assert OSDetector().detect_remote(ssh_executor=ssh) == OSType.MACOS


def test_detect_remote_linux_still_linux():
    ssh = FakeExecutor(responses={"uname -s": "Linux\n"})
    assert OSDetector().detect_remote(ssh_executor=ssh) == OSType.LINUX


# ---------------------------------------------------------------------------
# Disk scan
# ---------------------------------------------------------------------------

def test_scan_macos_classifies_disks():
    from core.disk_scanner import DiskScanner

    listing = {
        "WholeDisks": ["disk0", "disk4"],
        "AllDisksAndPartitions": [
            {"DeviceIdentifier": "disk0",
             "APFSVolumes": [{"DeviceIdentifier": "disk3s1", "MountPoint": "/"}]},
            {"DeviceIdentifier": "disk4",
             "Partitions": [{"DeviceIdentifier": "disk4s1", "MountPoint": ""}]},
        ],
    }
    root_info = {"ParentWholeDisk": "disk3"}
    container_info = {"APFSPhysicalStores": [{"APFSPhysicalStore": "disk0s2"}]}
    disk0_info = {
        "DeviceIdentifier": "disk0", "MediaName": "APPLE SSD AP1024",
        "TotalSize": 1000000000000, "SolidState": True, "Internal": True,
        "RemovableMedia": False, "BusProtocol": "PCI-Express", "MountPoint": "",
    }
    disk4_info = {
        "DeviceIdentifier": "disk4", "MediaName": "Samsung T7",
        "TotalSize": 512000000000, "SolidState": True, "Internal": False,
        "RemovableMedia": True, "BusProtocol": "USB", "MountPoint": "",
    }
    # FakeExecutor matches substrings in insertion order: exact ids before the
    # generic "diskutil info -plist /" and "diskutil list -plist".
    ex = FakeExecutor(responses={
        "diskutil info -plist disk0": _plist(disk0_info),
        "diskutil info -plist disk4": _plist(disk4_info),
        "diskutil info -plist disk3": _plist(container_info),
        "diskutil info -plist /": _plist(root_info),
        "diskutil list -plist": _plist(listing),
    })
    disks = {d.identifier: d for d in DiskScanner(ex, OSType.MACOS).scan()}

    # Whole disks are enumerated, plus a DiskInfo per partition/slice.
    whole = {i for i, d in disks.items() if not d.is_partition}
    assert whole == {"disk0", "disk4"}

    internal = disks["disk0"]
    assert internal.is_system is True          # via APFS physical store disk0s2
    assert internal.disk_type == "NVMe"
    assert internal.bus_type == "NVMe"

    external = disks["disk4"]
    assert external.is_system is False
    assert external.disk_type == "SSD"
    assert external.bus_type == "USB"
    assert external.size_bytes == 512000000000

    # The USB stick's partition is targetable and inherits the parent's
    # non-system status; a slice of the OS disk stays is_system=True.
    assert disks["disk4s1"].is_partition is True
    assert disks["disk4s1"].parent_identifier == "disk4"
    assert disks["disk4s1"].is_system is False
    assert disks["disk3s1"].is_system is True


def test_scan_macos_marks_all_internal_system_when_root_unresolved():
    from core.disk_scanner import DiskScanner

    listing = {"WholeDisks": ["disk0"], "AllDisksAndPartitions": []}
    info = {"DeviceIdentifier": "disk0", "TotalSize": 1, "SolidState": True,
            "Internal": True, "RemovableMedia": False, "BusProtocol": "PCI-Express"}
    ex = FakeExecutor(
        responses={"diskutil info -plist disk0": _plist(info),
                   "diskutil list -plist": _plist(listing)},
        errors={"diskutil info -plist /": "not mounted"},
    )
    disks = DiskScanner(ex, OSType.MACOS).scan()
    assert disks[0].is_system is True


# ---------------------------------------------------------------------------
# Wipe strategy
# ---------------------------------------------------------------------------

def _disk(identifier="disk4", *, disk_type="SSD", bus_type="USB",
          is_system=False, size_bytes=512000000000):
    return SimpleNamespace(
        identifier=identifier, disk_type=disk_type, bus_type=bus_type,
        is_system=is_system, size_bytes=size_bytes,
    )


def test_macos_strategy_auto_uses_secure_erase():
    from core.strategies import MacOSWipeStrategy

    ex = FakeExecutor()
    ok = MacOSWipeStrategy().execute(_disk(), ex)
    assert ok is True
    assert any("diskutil unmountDisk force /dev/disk4" in c for c in ex.calls)
    assert any("diskutil secureErase 0 disk4" in c for c in ex.calls)


def test_macos_strategy_passes_use_dd_raw_device():
    from core.strategies import MacOSWipeStrategy

    passes = [SimpleNamespace(kind="random", byte=None),
              SimpleNamespace(kind="fixed", byte=0)]
    ex = FakeExecutor()
    ok = MacOSWipeStrategy().execute(_disk(), ex, passes=passes)
    assert ok is True
    dd_calls = [c for c in ex.calls if c.startswith("dd ") and "of=/dev/rdisk4" in c]
    assert len(dd_calls) == 2
    assert any("if=/dev/urandom" in c for c in dd_calls)
    assert any("if=/dev/zero" in c for c in dd_calls)
    assert not any("secureErase" in c for c in ex.calls)


def test_macos_strategy_refuses_system_disk():
    from core.strategies import MacOSWipeStrategy

    ex = FakeExecutor()
    ok = MacOSWipeStrategy().execute(_disk(identifier="disk0", is_system=True), ex)
    assert ok is False
    assert not any("secureErase" in c or c.startswith("dd ") for c in ex.calls)


def test_macos_strategy_refuses_apple_fabric_internal():
    from core.strategies import MacOSWipeStrategy

    ex = FakeExecutor()
    disk = _disk(identifier="disk0", disk_type="NVMe", bus_type="Apple Fabric")
    ok = MacOSWipeStrategy().execute(disk, ex)
    assert ok is False
    assert not any("secureErase" in c or c.startswith("dd ") for c in ex.calls)


# ---------------------------------------------------------------------------
# Verification
# ---------------------------------------------------------------------------

def test_verify_macos_reads_raw_device_and_passes_on_zeros():
    from core.verifier import WipeVerifier

    zeros_od = "0000000 " + "00 " * 16 + "\n0000020\n"
    ex = FakeExecutor(responses={"od -An": zeros_od})
    disk = _disk(size_bytes=4096 * 4096)
    result = WipeVerifier().verify(disk, ex, OSType.MACOS,
                                  sample_count=4, expected="zeroed")
    assert result["verified"] is True
    assert any("/dev/rdisk4" in c for c in ex.calls)
