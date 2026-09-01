"""Platform adapter selection and behaviour (mocked — runs on any OS)."""

import os

import pytest

from core.os_detector import OSType, OSDetector
from core.platforms import (
    get_adapter, LinuxAdapter, DarwinAdapter, WindowsAdapter,
)


@pytest.mark.parametrize("sysname,expect", [
    ("Linux", LinuxAdapter),
    ("Darwin", DarwinAdapter),
    ("Windows", WindowsAdapter),
])
def test_get_adapter_follows_platform_system(monkeypatch, sysname, expect):
    monkeypatch.setattr("platform.system", lambda: sysname)
    assert isinstance(get_adapter(), expect)


@pytest.mark.parametrize("os_type,expect", [
    (OSType.LINUX, LinuxAdapter),
    (OSType.DARWIN, DarwinAdapter),
    (OSType.WINDOWS, WindowsAdapter),
])
def test_get_adapter_by_os_type(os_type, expect):
    assert isinstance(get_adapter(os_type), expect)


def test_get_adapter_rejects_unsupported():
    with pytest.raises(ValueError):
        get_adapter(OSType.UNSUPPORTED)


def test_linux_raw_device_path():
    a = LinuxAdapter()
    assert a.raw_device_path("sda") == "/dev/sda"
    assert a.raw_device_path("/dev/sdb") == "/dev/sdb"


def test_darwin_raw_device_path_prefers_raw_node():
    a = DarwinAdapter()
    assert a.raw_device_path("disk0") == "/dev/rdisk0"
    assert a.raw_device_path("/dev/disk2") == "/dev/rdisk2"


def test_windows_raw_device_path():
    a = WindowsAdapter()
    assert a.raw_device_path("0") == r"\\.\PhysicalDrive0"
    assert a.raw_device_path("PhysicalDrive1") == r"\\.\PhysicalDrive1"
    assert a.raw_device_path(r"\\.\PhysicalDrive2") == r"\\.\PhysicalDrive2"


def test_posix_is_admin_reads_geteuid(monkeypatch):
    monkeypatch.setattr(os, "geteuid", lambda: 0, raising=False)
    assert LinuxAdapter().is_admin() is True
    monkeypatch.setattr(os, "geteuid", lambda: 1000, raising=False)
    assert LinuxAdapter().is_admin() is False


def test_windows_is_admin_calls_shell32(monkeypatch):
    class _Shell32:
        @staticmethod
        def IsUserAnAdmin():
            return 1

    class _Windll:
        shell32 = _Shell32()

    import ctypes

    monkeypatch.setattr(ctypes, "windll", _Windll(), raising=False)
    assert WindowsAdapter().is_admin() is True


def test_os_detector_maps_darwin(monkeypatch):
    monkeypatch.setattr("platform.system", lambda: "Darwin")
    assert OSDetector().detect_local() == OSType.DARWIN


def test_os_detector_remote_ssh_darwin():
    class _Exec:
        def run_command(self, cmd):
            return "Darwin\n"

    assert OSDetector().detect_remote(ssh_executor=_Exec()) == OSType.DARWIN
