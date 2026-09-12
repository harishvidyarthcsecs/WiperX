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
        assert result in [OSType.LINUX, OSType.WINDOWS, OSType.MACOS,
                          OSType.UNSUPPORTED]

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
# Disk Scanner - Linux fail-closed detection (A4: ENG-01 / ENG-02 / ENG-03)
# ---------------------------------------------------------------------------

class TestDiskScannerLinuxFailClosed:
    @staticmethod
    def _make_executor(
        lsblk_out, root_cmd_result=None, root_cmd_error=None,
        mount_cmd_result=None, mount_cmd_error=None,
    ):
        from unittest.mock import MagicMock
        from core.disk_scanner import DiskScanner

        def run_command(cmd, *a, **k):
            if cmd == DiskScanner.LINUX_ROOT_CMD:
                if root_cmd_error:
                    raise root_cmd_error
                return root_cmd_result
            if cmd == DiskScanner.LINUX_MOUNT_CMD:
                if mount_cmd_error:
                    raise mount_cmd_error
                return mount_cmd_result
            return lsblk_out

        executor = MagicMock()
        executor.run_command.side_effect = run_command
        return executor

    def test_root_device_detection_failure_is_unknown_not_false(self):
        """df/awk/tail unavailable -> is_system/is_mounted are None for every
        disk, never silently False (ENG-01)."""
        from core.disk_scanner import DiskScanner
        from core.os_detector import OSType

        lsblk = "sda\t0\tsata\t500000000000\tSamsung SSD\tSERIAL123\n"
        executor = self._make_executor(
            lsblk_out=lsblk,
            root_cmd_error=RuntimeError("df: command not found"),
            mount_cmd_result="/dev/sda1 / ext4 rw 0 0\n",
        )
        disks = DiskScanner(executor=executor, os_type=OSType.LINUX).scan()

        assert len(disks) == 1
        assert disks[0].is_system is None
        assert disks[0].is_mounted is None

    def test_mount_table_detection_failure_is_unknown_not_false(self):
        """/proc/mounts unreadable -> same fail-closed behaviour (ENG-02)."""
        from core.disk_scanner import DiskScanner
        from core.os_detector import OSType

        lsblk = "sda\t0\tsata\t500000000000\tSamsung SSD\tSERIAL123\n"
        executor = self._make_executor(
            lsblk_out=lsblk,
            root_cmd_result="/dev/sda1\n",
            mount_cmd_error=PermissionError("/proc/mounts: permission denied"),
        )
        disks = DiskScanner(executor=executor, os_type=OSType.LINUX).scan()

        assert disks[0].is_system is None
        assert disks[0].is_mounted is None

    def test_successful_detection_still_flags_correctly(self):
        """Sanity check: the normal (non-failure) path still yields real
        booleans, not None, once detection succeeds."""
        from core.disk_scanner import DiskScanner
        from core.os_detector import OSType

        lsblk = (
            "sda\t0\tsata\t500000000000\tSystem Disk\tSER1\n"
            "sdb\t0\tusb\t64000000000\tUSB Stick\tSER2\n"
        )
        executor = self._make_executor(
            lsblk_out=lsblk,
            root_cmd_result="/dev/sda1\n",
            mount_cmd_result="/dev/sda1 / ext4 rw 0 0\n",
        )
        disks = DiskScanner(executor=executor, os_type=OSType.LINUX).scan()
        by_name = {d.identifier: d for d in disks}

        assert by_name["sda"].is_system is True
        assert by_name["sda"].is_mounted is True
        assert by_name["sdb"].is_system is False
        assert by_name["sdb"].is_mounted is False

    def test_exact_device_match_no_false_positive_substring(self):
        """ENG-03: a device name must not falsely match a DIFFERENT disk's
        partition just because it's a string prefix (e.g. "sd" is a prefix
        of "/dev/sdb1") - exact base-device comparison, not substring `in`."""
        from core.disk_scanner import DiskScanner
        from core.os_detector import OSType

        lsblk = (
            "sd\t0\tsata\t500000000000\tContrived Disk\tSER1\n"
            "sdb\t0\tsata\t1000000000000\tReal Disk\tSER2\n"
        )
        executor = self._make_executor(
            lsblk_out=lsblk,
            root_cmd_result="/dev/sdb1\n",
            mount_cmd_result="/dev/sdb1 / ext4 rw 0 0\n",
        )
        disks = DiskScanner(executor=executor, os_type=OSType.LINUX).scan()
        by_name = {d.identifier: d for d in disks}

        assert by_name["sdb"].is_system is True
        assert by_name["sdb"].is_mounted is True
        assert by_name["sd"].is_system is False
        assert by_name["sd"].is_mounted is False

    def test_unsupported_os_scan_raises_value_error(self):
        """Reconciles the ValueError/RuntimeError mismatch noted in
        FAILURE_MODES.md section 10 - matches get_strategy's convention for
        the same 'unsupported OS' condition."""
        from core.disk_scanner import DiskScanner
        from core.os_detector import OSType

        scanner = DiskScanner(executor=None, os_type=OSType.UNSUPPORTED)
        with pytest.raises(ValueError):
            scanner.scan()


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

    def test_nvme_strategy_refuses_unexpected_identifier(self):
        """ENG-06: a malformed/unexpected NVMe identifier must refuse the
        erase, never silently fall back to a hard-coded nvme0n1 device path
        (which could crypto-erase the wrong namespace entirely)."""
        from unittest.mock import MagicMock
        from core.strategies import LinuxNVMeWipeStrategy

        disk = self._make_disk("NVMe", "NVMe", "not-an-nvme-id")
        executor = MagicMock()
        ok = LinuxNVMeWipeStrategy().execute(disk, executor, log_callback=None)

        assert ok is False
        executor.run_command.assert_not_called()

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

    def test_macos_gets_diskutil(self):
        from core.strategies import get_strategy, MacOSWipeStrategy
        from core.os_detector import OSType
        disk = self._make_disk("SSD", "USB", "disk4")
        strategy = get_strategy(disk, OSType.MACOS)
        assert isinstance(strategy, MacOSWipeStrategy)

    def test_unsupported_os_raises(self):
        from core.strategies import get_strategy
        from core.os_detector import OSType
        disk = self._make_disk("HDD", "SATA")
        with pytest.raises(ValueError):
            get_strategy(disk, OSType.UNSUPPORTED)


# ---------------------------------------------------------------------------
# ENG-09: a missing external binary must surface as a clear, actionable
# message before the destructive command runs, not as an opaque failure.
# ---------------------------------------------------------------------------

class TestBinaryPreflight:
    def _make_disk(self, disk_type, bus_type, identifier):
        from core.disk_scanner import DiskInfo
        return DiskInfo(identifier=identifier, disk_type=disk_type, bus_type=bus_type)

    def test_missing_shred_refuses_without_running_destructive_command(self):
        from unittest.mock import MagicMock
        from core.strategies import LinuxHDDWipeStrategy

        disk = self._make_disk("HDD", "SATA", "sdb")
        executor = MagicMock()
        executor.run_command.return_value = ""  # `command -v shred` finds nothing

        ok = LinuxHDDWipeStrategy().execute(disk, executor, log_callback=None)

        assert ok is False
        executor.run_command.assert_called_once_with("command -v shred", timeout=10)

    def test_missing_nvme_binary_refuses(self):
        from unittest.mock import MagicMock
        from core.strategies import LinuxNVMeWipeStrategy

        disk = self._make_disk("NVMe", "NVMe", "nvme0n1")
        executor = MagicMock()
        executor.run_command.return_value = ""

        ok = LinuxNVMeWipeStrategy().execute(disk, executor, log_callback=None)

        assert ok is False

    def test_present_binary_allows_execute_to_proceed(self):
        from unittest.mock import MagicMock
        from core.strategies import LinuxHDDWipeStrategy

        disk = self._make_disk("HDD", "SATA", "sdb")
        executor = MagicMock()
        executor.run_command.return_value = "/usr/bin/shred"

        ok = LinuxHDDWipeStrategy().execute(disk, executor, log_callback=None)

        assert ok is True
        # preflight + the actual shred command
        assert executor.run_command.call_count == 2


# ---------------------------------------------------------------------------
# ENG-12: every interpolated device path/identifier must be shell-quoted
# before it reaches an executor's shell=True command string.
# ---------------------------------------------------------------------------

class TestDevicePathQuoting:
    def _make_disk(self, disk_type, bus_type, identifier):
        from core.disk_scanner import DiskInfo
        return DiskInfo(identifier=identifier, disk_type=disk_type, bus_type=bus_type)

    def test_linux_hdd_shred_quotes_device_path(self):
        import shlex
        from unittest.mock import MagicMock
        from core.strategies import LinuxHDDWipeStrategy

        evil = "sda; rm -rf /"
        disk = self._make_disk("HDD", "SATA", evil)
        executor = MagicMock()
        executor.run_command.return_value = "/usr/bin/shred"  # truthy: passes preflight

        LinuxHDDWipeStrategy().execute(disk, executor, log_callback=None)

        cmd = executor.run_command.call_args[0][0]
        assert shlex.quote(f"/dev/{evil}") in cmd
        assert "; rm -rf /" not in cmd.split(shlex.quote(f"/dev/{evil}"))[0]

    def test_windows_diskpart_refuses_non_numeric_disk_number(self):
        """ENG-12: disk_number is embedded unescaped into three different
        Windows quoting dialects (PowerShell, diskpart script, cmd path) -
        shlex.quote can't protect any of them. A non-numeric identifier must
        be refused outright, not quoted-and-passed-through."""
        from unittest.mock import MagicMock
        from core.strategies import WindowsWipeStrategy

        evil = "1 & del C:\\Windows"
        disk = self._make_disk("HDD", "SATA", evil)
        executor = MagicMock()

        ok = WindowsWipeStrategy().execute(disk, executor, log_callback=None)

        assert ok is False
        executor.run_command.assert_not_called()

    def test_windows_diskpart_accepts_plain_numeric_disk_number(self):
        from unittest.mock import MagicMock
        from core.strategies import WindowsWipeStrategy

        disk = self._make_disk("HDD", "SATA", "1")
        executor = MagicMock()
        executor.run_command.return_value = ""

        ok = WindowsWipeStrategy().execute(disk, executor, log_callback=None)

        assert ok is True
        executor.run_command.assert_called()

    def test_macos_secure_erase_quotes_identifier(self):
        import shlex
        from unittest.mock import MagicMock
        from core.strategies import MacOSWipeStrategy

        evil = "disk4; rm -rf /"
        disk = self._make_disk("SSD", "USB", evil)
        executor = MagicMock()
        executor.run_command.return_value = ""

        MacOSWipeStrategy().execute(disk, executor, log_callback=None)

        erase_cmd = executor.run_command.call_args_list[-1][0][0]
        assert shlex.quote(evil) in erase_cmd


# ---------------------------------------------------------------------------
# ENG-17: remote WinRM privilege check must actually verify Administrator
# role, not just log the identity name and pass unconditionally.
# ---------------------------------------------------------------------------

class TestRemoteWindowsPrivilegeCheck:
    def _manager(self):
        from core.execution_manager import ExecutionManager
        return ExecutionManager()

    def test_non_admin_remote_user_is_blocked(self):
        from unittest.mock import MagicMock
        from core.os_detector import OSType

        executor = MagicMock()
        executor.run_command.return_value = "HOST\\bob\nFalse"
        with pytest.raises(PermissionError):
            self._manager()._check_privileges(executor, OSType.WINDOWS, log_fn=lambda *_: None)

    def test_admin_remote_user_passes(self):
        from unittest.mock import MagicMock
        from core.os_detector import OSType

        executor = MagicMock()
        executor.run_command.return_value = "HOST\\admin\nTrue"
        # Should not raise.
        self._manager()._check_privileges(executor, OSType.WINDOWS, log_fn=lambda *_: None)


# ---------------------------------------------------------------------------
# ENG-15/16: SSH executor drains the full channel output (not truncated at
# 64KB) and sets a transport keepalive.
# ---------------------------------------------------------------------------

class TestSSHExecutorDrainAndKeepalive:
    class _FakeChannel:
        """Yields output across several recv() calls before exit_status_ready."""

        def __init__(self, out_chunks, exit_status=0):
            self._out_chunks = list(out_chunks)
            self._exit_status = exit_status

        def recv_ready(self):
            return bool(self._out_chunks)

        def recv(self, _bufsize):
            return self._out_chunks.pop(0) if self._out_chunks else b""

        def recv_stderr_ready(self):
            return False

        def recv_stderr(self, _bufsize):
            return b""

        def exit_status_ready(self):
            return not self._out_chunks

        def recv_exit_status(self):
            return self._exit_status

    def test_drain_channel_concatenates_all_chunks_not_truncated(self):
        from core.executors.ssh_executor import SSHExecutor

        # Bypass __init__'s paramiko/key-file requirements.
        executor = SSHExecutor.__new__(SSHExecutor)
        channel = self._FakeChannel([b"a" * 70000, b"b" * 70000, b"tail"])

        output, error_output = executor._drain_channel(channel)

        assert len(output) == 140000 + 4
        assert output.endswith("tail")
        assert error_output == ""

    def test_connect_sets_transport_keepalive(self, monkeypatch):
        from unittest.mock import MagicMock
        import core.executors.ssh_executor as ssh_mod

        fake_transport = MagicMock()
        fake_client = MagicMock()
        fake_client.get_transport.return_value = fake_transport
        monkeypatch.setattr(ssh_mod, "paramiko", MagicMock(SSHClient=lambda: fake_client))
        monkeypatch.setattr(ssh_mod.os.path, "isfile", lambda _p: True)

        from core.executors.ssh_executor import SSHExecutor

        executor = SSHExecutor.__new__(SSHExecutor)
        executor.hostname = "host"
        executor.username = "user"
        executor.port = 22
        executor.key_path = "/tmp/key"
        executor.known_hosts_path = "/tmp/known_hosts"
        executor._client = None

        executor.connect()

        fake_transport.set_keepalive.assert_called_once_with(SSHExecutor.KEEPALIVE_INTERVAL)


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

    def test_unknown_safety_status_is_blocked(self):
        """A disk whose system/mounted status could not be determined (None)
        must be refused outright, never treated as safe (ENG-01/ENG-02)."""
        from core.execution_manager import ExecutionManager, WipeRequest, ExecutionMode
        from core.disk_scanner import DiskInfo
        from unittest.mock import patch, MagicMock

        manager = ExecutionManager()
        mock_disk = DiskInfo(
            identifier="sda",
            model="Unknown-safety Disk",
            is_system=None,
            is_mounted=None,
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

            with patch.object(manager, "_check_privileges"):
                request = WipeRequest(
                    disk_identifier="sda",
                    confirmed_disk_name="sda",
                    mode=ExecutionMode.LOCAL,
                )
                result = manager.execute_wipe(request)

        assert result.success is False
        assert "unknown safety status" in (result.error or "").lower()

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

    def test_mounted_disk_is_blocked_by_default(self):
        """A mounted disk is refused unless force_unmount is explicitly set."""
        from core.execution_manager import ExecutionManager, WipeRequest, ExecutionMode
        from core.disk_scanner import DiskInfo
        from unittest.mock import patch, MagicMock

        manager = ExecutionManager()
        disk = DiskInfo(identifier="disk8", is_system=False, is_mounted=True, bus_type="USB")

        with patch.object(manager, "_build_executor_and_detect_os") as mock_build, \
             patch("core.execution_manager.DiskScanner") as mock_scanner_cls, \
             patch.object(manager, "_check_privileges"):

            from core.os_detector import OSType
            mock_build.return_value = (MagicMock(), OSType.MACOS)
            mock_scanner = MagicMock()
            mock_scanner.scan.return_value = [disk]
            mock_scanner_cls.return_value = mock_scanner

            request = WipeRequest(disk_identifier="disk8", confirmed_disk_name="disk8",
                                  mode=ExecutionMode.LOCAL)
            result = manager.execute_wipe(request)

        assert result.success is False
        assert "mounted" in (result.error or "").lower()

    def test_mounted_removable_with_force_unmount_proceeds(self):
        """force_unmount + non-system + removable bus -> the wipe proceeds."""
        from core.execution_manager import ExecutionManager, WipeRequest, ExecutionMode
        from core.disk_scanner import DiskInfo
        from unittest.mock import patch, MagicMock

        manager = ExecutionManager()
        disk = DiskInfo(identifier="disk8", is_system=False, is_mounted=True, bus_type="USB")

        with patch.object(manager, "_build_executor_and_detect_os") as mock_build, \
             patch("core.execution_manager.DiskScanner") as mock_scanner_cls, \
             patch.object(manager, "_check_privileges"), \
             patch("core.execution_manager.get_strategy") as mock_get_strategy, \
             patch("core.verifier.WipeVerifier.verify", return_value={"verified": True}):

            from core.os_detector import OSType
            mock_build.return_value = (MagicMock(), OSType.MACOS)
            mock_scanner = MagicMock()
            mock_scanner.scan.return_value = [disk]
            mock_scanner_cls.return_value = mock_scanner

            strat = MagicMock()
            strat.name = "MacOSWipeStrategy"
            strat.execute.return_value = True
            mock_get_strategy.return_value = strat

            request = WipeRequest(disk_identifier="disk8", confirmed_disk_name="disk8",
                                  mode=ExecutionMode.LOCAL, force_unmount=True)
            result = manager.execute_wipe(request)

        assert result.success is True

    def test_mounted_internal_with_force_unmount_still_blocked(self):
        """force_unmount never overrides the internal/system-adjacent block."""
        from core.execution_manager import ExecutionManager, WipeRequest, ExecutionMode
        from core.disk_scanner import DiskInfo
        from unittest.mock import patch, MagicMock

        manager = ExecutionManager()
        disk = DiskInfo(identifier="disk2", is_system=False, is_mounted=True,
                        bus_type="Apple Fabric")

        with patch.object(manager, "_build_executor_and_detect_os") as mock_build, \
             patch("core.execution_manager.DiskScanner") as mock_scanner_cls, \
             patch.object(manager, "_check_privileges"):

            from core.os_detector import OSType
            mock_build.return_value = (MagicMock(), OSType.MACOS)
            mock_scanner = MagicMock()
            mock_scanner.scan.return_value = [disk]
            mock_scanner_cls.return_value = mock_scanner

            request = WipeRequest(disk_identifier="disk2", confirmed_disk_name="disk2",
                                  mode=ExecutionMode.LOCAL, force_unmount=True)
            result = manager.execute_wipe(request)

        assert result.success is False
        assert "mounted" in (result.error or "").lower()


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

    def test_oserror_from_subprocess_wrapped_as_runtimeerror(self):
        """ENG-14: a raw OSError/FileNotFoundError from subprocess.run itself
        (fork failure, no shell, exec permission denied) must not propagate
        unwrapped - only RuntimeError is part of this method's contract."""
        from unittest.mock import patch
        from core.executors import LocalExecutor

        executor = LocalExecutor()
        with patch("subprocess.run", side_effect=FileNotFoundError("no /bin/sh")):
            with pytest.raises(RuntimeError):
                executor.run_command("echo hi")


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
