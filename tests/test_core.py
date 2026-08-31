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


# ---------------------------------------------------------------------------
# Method routing (Phase 2)
# ---------------------------------------------------------------------------

class TestWipeMethodRouting:
    def _run(self, method):
        from unittest.mock import MagicMock, patch

        from core.execution_manager import (
            ExecutionManager, ExecutionMode, WipeRequest,
        )
        from core.disk_scanner import DiskInfo
        from core.os_detector import OSType

        manager = ExecutionManager()
        disk = DiskInfo(identifier="sdb", is_system=False, is_mounted=False)
        disk.size_bytes = 64 * 1024 * 1024
        disk.bus_type = "USB"

        captured = {}

        def fake_execute(**kwargs):
            captured["passes"] = kwargs.get("passes")
            return True

        with patch.object(manager, "_build_executor_and_detect_os") as mock_build, \
             patch("core.execution_manager.DiskScanner") as mock_scanner_cls, \
             patch.object(manager, "_check_privileges"), \
             patch("core.execution_manager.get_strategy") as mock_get_strategy, \
             patch("core.verifier.WipeVerifier.verify", return_value={"verified": True}):

            mock_executor = MagicMock()
            mock_build.return_value = (mock_executor, OSType.LINUX)
            mock_scanner = MagicMock()
            mock_scanner.scan.return_value = [disk]
            mock_scanner_cls.return_value = mock_scanner

            strat = MagicMock()
            strat.name = "MockStrategy"
            strat.execute.side_effect = fake_execute
            mock_get_strategy.return_value = strat

            request = WipeRequest(
                disk_identifier="sdb", confirmed_disk_name="sdb",
                mode=ExecutionMode.LOCAL, method=method,
            )
            result = manager.execute_wipe(request)
        return result, captured.get("passes")

    def test_auto_passes_none(self):
        result, passes = self._run("auto")
        assert result.success is True
        assert passes is None
        assert result.method == "auto"
        assert result.pass_count == 0

    def test_dod_builds_three_pass_list(self):
        result, passes = self._run("dod")
        assert passes is not None and len(passes) == 3
        assert result.method == "dod"
        assert result.pass_count == 3

    def test_gutmann_builds_35_pass_list(self):
        _result, passes = self._run("gutmann")
        assert passes is not None and len(passes) == 35

    def test_unknown_method_falls_back_to_auto(self):
        result, passes = self._run("bogus-method")
        assert passes is None
        assert result.method == "auto"

    def test_ata_secure_erase_builds_no_pass_list(self):
        """ata-secure-erase is a hardware op - no software pass list, and
        the method name must survive (not get reset to "auto" like an
        actually-unknown method would)."""
        result, passes = self._run("ata-secure-erase")
        assert passes is None
        assert result.method == "ata-secure-erase"


class TestHdparmSecureEraseStrategy:
    def _make_disk(self, bus_type="SATA", identifier="sda"):
        from core.disk_scanner import DiskInfo
        return DiskInfo(identifier=identifier, disk_type="SSD", bus_type=bus_type)

    def test_get_strategy_routes_sata_to_hdparm(self):
        from core.strategies import get_strategy, LinuxHdparmSecureEraseStrategy
        from core.os_detector import OSType
        strategy = get_strategy(self._make_disk("SATA"), OSType.LINUX, method="ata-secure-erase")
        assert isinstance(strategy, LinuxHdparmSecureEraseStrategy)

    def test_get_strategy_rejects_usb_for_ata_secure_erase(self):
        from core.strategies import get_strategy
        from core.os_detector import OSType
        with pytest.raises(ValueError):
            get_strategy(self._make_disk("USB"), OSType.LINUX, method="ata-secure-erase")

    def test_get_strategy_rejects_windows_for_ata_secure_erase(self):
        from core.strategies import get_strategy
        from core.os_detector import OSType
        with pytest.raises(ValueError):
            get_strategy(self._make_disk("SATA"), OSType.WINDOWS, method="ata-secure-erase")

    def _executor(self, responses):
        """A mock executor whose run_command returns/raises per a dict keyed
        by a substring of the command."""
        from unittest.mock import MagicMock

        def run_command(cmd, timeout=30):
            for key, outcome in responses.items():
                if key in cmd:
                    if isinstance(outcome, Exception):
                        raise outcome
                    return outcome
            raise AssertionError(f"unexpected command: {cmd}")

        executor = MagicMock()
        executor.run_command.side_effect = run_command
        return executor

    def test_execute_succeeds_when_unlocked_and_not_frozen(self):
        from core.strategies import LinuxHdparmSecureEraseStrategy
        executor = self._executor({
            "hdparm -I": "Security: \n\tsupported\n\tnot\tenabled\n\tnot\tlocked\n\tnot\tfrozen\n",
            "security-set-pass": "",
            "security-erase": "",
        })
        strategy = LinuxHdparmSecureEraseStrategy()
        assert strategy.execute(self._make_disk(), executor) is True

    def test_execute_blocks_on_frozen_drive(self):
        from core.strategies import LinuxHdparmSecureEraseStrategy
        executor = self._executor({
            "hdparm -I": "Security: \n\tsupported\n\tnot\tenabled\n\tnot\tlocked\n\tfrozen\n",
        })
        strategy = LinuxHdparmSecureEraseStrategy()
        assert strategy.execute(self._make_disk(), executor) is False
        # must not even attempt to set a password on a frozen drive
        assert not any(
            "security-set-pass" in str(c) for c in executor.run_command.call_args_list
        )

    def test_execute_reports_unsupported_security_feature(self):
        from core.strategies import LinuxHdparmSecureEraseStrategy
        executor = self._executor({
            "hdparm -I": "Security: \n\tnot\tsupported\n",
        })
        strategy = LinuxHdparmSecureEraseStrategy()
        assert strategy.execute(self._make_disk(), executor) is False

    def test_execute_fails_cleanly_when_set_pass_fails(self):
        from core.strategies import LinuxHdparmSecureEraseStrategy
        executor = self._executor({
            "hdparm -I": "Security: \n\tsupported\n\tnot\tfrozen\n",
            "security-set-pass": RuntimeError("device busy"),
        })
        strategy = LinuxHdparmSecureEraseStrategy()
        assert strategy.execute(self._make_disk(), executor) is False

    def test_execute_fails_cleanly_when_erase_fails(self):
        from core.strategies import LinuxHdparmSecureEraseStrategy
        executor = self._executor({
            "hdparm -I": "Security: \n\tsupported\n\tnot\tfrozen\n",
            "security-set-pass": "",
            "security-erase": RuntimeError("erase aborted by drive"),
        })
        strategy = LinuxHdparmSecureEraseStrategy()
        assert strategy.execute(self._make_disk(), executor) is False
