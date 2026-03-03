# tests/test_core.py
"""
Basic unit tests for WiperX core modules.
Run with: pytest tests/ -v
"""

import sys
import os
import pytest

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))


# ---------------------------------------------------------------------------
# OS Detector Tests
# ---------------------------------------------------------------------------

class TestOSDetector:
    def test_detect_local_returns_valid_os(self):
        from core.os_detector import OSDetector, OSType
        detector = OSDetector()
        result = detector.detect_local()
        assert result in [OSType.LINUX, OSType.WINDOWS, OSType.UNSUPPORTED]

    def test_detect_remote_no_executors_returns_unsupported(self):
        from core.os_detector import OSDetector, OSType
        detector = OSDetector()
        result = detector.detect_remote(ssh_executor=None, winrm_executor=None)
        assert result == OSType.UNSUPPORTED

    def test_get_os_info_returns_dict(self):
        from core.os_detector import OSDetector
        detector = OSDetector()
        info = detector.get_os_info()
        assert "os_type" in info
        assert "hostname" in info
        assert "architecture" in info


# ---------------------------------------------------------------------------
# Disk Scanner Tests
# ---------------------------------------------------------------------------

class TestDiskInfo:
    def test_disk_info_display_name(self):
        from core.disk_scanner import DiskInfo
        disk = DiskInfo(
            identifier="sda",
            model="Samsung 870 EVO",
            size_human="500.0 GB",
            disk_type="SSD",
        )
        name = disk.display_name()
        assert "sda" in name
        assert "Samsung" in name

    def test_bytes_to_human_conversion(self):
        from core.disk_scanner import DiskScanner
        assert DiskScanner._bytes_to_human(0) == "Unknown"
        assert "GB" in DiskScanner._bytes_to_human(500 * 1024 ** 3)
        assert "TB" in DiskScanner._bytes_to_human(2 * 1024 ** 4)


# ---------------------------------------------------------------------------
# Strategy Selection Tests
# ---------------------------------------------------------------------------

class TestStrategyFactory:
    def _make_disk(self, disk_type, bus_type, identifier="sda"):
        from core.disk_scanner import DiskInfo
        return DiskInfo(
            identifier=identifier,
            disk_type=disk_type,
            bus_type=bus_type,
        )

    def test_linux_hdd_gets_shred(self):
        from core.strategies import get_strategy, LinuxHDDWipeStrategy
        from core.os_detector import OSType
        disk = self._make_disk("HDD", "SATA")
        strategy = get_strategy(disk, OSType.LINUX)
        assert isinstance(strategy, LinuxHDDWipeStrategy)

    def test_linux_nvme_gets_nvme_format(self):
        from core.strategies import get_strategy, LinuxNVMeWipeStrategy
        from core.os_detector import OSType
        disk = self._make_disk("NVMe", "NVMe", "nvme0n1")
        strategy = get_strategy(disk, OSType.LINUX)
        assert isinstance(strategy, LinuxNVMeWipeStrategy)

    def test_linux_usb_gets_dd(self):
        from core.strategies import get_strategy, LinuxUSBWipeStrategy
        from core.os_detector import OSType
        disk = self._make_disk("SSD", "USB")
        strategy = get_strategy(disk, OSType.LINUX)
        assert isinstance(strategy, LinuxUSBWipeStrategy)

    def test_linux_ssd_gets_blkdiscard(self):
        from core.strategies import get_strategy, LinuxSSDWipeStrategy
        from core.os_detector import OSType
        disk = self._make_disk("SSD", "SATA")
        strategy = get_strategy(disk, OSType.LINUX)
        assert isinstance(strategy, LinuxSSDWipeStrategy)

    def test_windows_gets_diskpart(self):
        from core.strategies import get_strategy, WindowsWipeStrategy
        from core.os_detector import OSType
        disk = self._make_disk("HDD", "SATA", "1")
        strategy = get_strategy(disk, OSType.WINDOWS)
        assert isinstance(strategy, WindowsWipeStrategy)

    def test_unsupported_os_raises(self):
        from core.strategies import get_strategy
        from core.os_detector import OSType
        disk = self._make_disk("HDD", "SATA")
        with pytest.raises(ValueError):
            get_strategy(disk, OSType.UNSUPPORTED)


# ---------------------------------------------------------------------------
# Safety Check Tests (mocked)
# ---------------------------------------------------------------------------

class TestExecutionManagerSafety:
    def test_system_disk_is_blocked(self, tmp_path):
        """System disk should be rejected regardless of confirmation."""
        from core.execution_manager import ExecutionManager, WipeRequest, ExecutionMode
        from core.disk_scanner import DiskInfo
        from unittest.mock import patch, MagicMock

        manager = ExecutionManager()

        # Mock scan to return a system disk
        mock_disk = DiskInfo(
            identifier="sda",
            model="Test Disk",
            is_system=True,
            is_mounted=True,
        )

        with patch.object(manager, "_build_executor_and_detect_os") as mock_build, \
             patch("core.execution_manager.DiskScanner") as mock_scanner_cls:

            from core.os_detector import OSType
            mock_executor = MagicMock()
            mock_executor.close = MagicMock()
            mock_build.return_value = (mock_executor, OSType.LINUX)

            mock_scanner = MagicMock()
            mock_scanner.scan.return_value = [mock_disk]
            mock_scanner_cls.return_value = mock_scanner

            # Also mock privilege check
            with patch.object(manager, "_check_privileges"):
                request = WipeRequest(
                    disk_identifier="sda",
                    confirmed_disk_name="sda",
                    mode=ExecutionMode.LOCAL,
                )
                result = manager.execute_wipe(request)

        assert result.success is False
        assert "SYSTEM DISK" in (result.error or "")

    def test_name_mismatch_is_blocked(self):
        """Mismatched confirmation name should block wipe."""
        from core.execution_manager import ExecutionManager, WipeRequest, ExecutionMode
        from core.disk_scanner import DiskInfo
        from unittest.mock import patch, MagicMock

        manager = ExecutionManager()
        mock_disk = DiskInfo(identifier="sdb", is_system=False, is_mounted=False)

        with patch.object(manager, "_build_executor_and_detect_os") as mock_build, \
             patch("core.execution_manager.DiskScanner") as mock_scanner_cls, \
             patch.object(manager, "_check_privileges"):

            from core.os_detector import OSType
            mock_executor = MagicMock()
            mock_executor.close = MagicMock()
            mock_build.return_value = (mock_executor, OSType.LINUX)

            mock_scanner = MagicMock()
            mock_scanner.scan.return_value = [mock_disk]
            mock_scanner_cls.return_value = mock_scanner

            request = WipeRequest(
                disk_identifier="sdb",
                confirmed_disk_name="sdc",  # WRONG NAME
                mode=ExecutionMode.LOCAL,
            )
            result = manager.execute_wipe(request)

        assert result.success is False
        assert "Safety FAILED" in (result.error or "")


# ---------------------------------------------------------------------------
# Local Executor Tests
# ---------------------------------------------------------------------------

class TestLocalExecutor:
    def test_run_echo_command(self):
        from core.executors import LocalExecutor
        executor = LocalExecutor()
        result = executor.run_command("echo hello_wiperx")
        assert "hello_wiperx" in result

    def test_failed_command_raises(self):
        from core.executors import LocalExecutor
        executor = LocalExecutor()
        with pytest.raises(RuntimeError):
            executor.run_command("exit 1", timeout=5)

    def test_test_connection_always_true(self):
        from core.executors import LocalExecutor
        executor = LocalExecutor()
        assert executor.test_connection() is True
