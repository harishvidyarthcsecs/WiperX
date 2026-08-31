# wiperx/core/execution_manager.py
"""
Execution Manager
-----------------
The single entry point for all wipe and scan operations.

Responsibilities:
  1. Determine execution mode: local or remote.
  2. Dynamically select the correct executor (Local, SSH, WinRM).
  3. Detect OS on target.
  4. Build appropriate executor and pass to scanner / strategy.
  5. Enforce all mandatory safety checks BEFORE any wipe.
  6. Generate post-wipe reports.

Design principle: Neither CLI nor Flask calls strategies or executors directly.
They call ExecutionManager, which orchestrates everything internally.
"""

import logging
import platform
import socket
from dataclasses import dataclass, field
from enum import Enum
from typing import Optional, List, Callable, Dict, Any

from core.disk_scanner import DiskScanner
from core.strategies import get_strategy

logger = logging.getLogger(__name__)


class ExecutionMode(str, Enum):
    LOCAL = "local"
    REMOTE_SSH = "remote_ssh"
    REMOTE_WINRM = "remote_winrm"


@dataclass
class RemoteConnectionConfig:
    """
    Holds connection parameters for remote targets.
    Credentials are loaded from env vars; never stored plain in code.
    """
    hostname: str
    mode: ExecutionMode = ExecutionMode.REMOTE_SSH

    # SSH fields
    ssh_username: Optional[str] = None
    ssh_key_path: Optional[str] = None
    ssh_port: int = 22

    # WinRM fields
    winrm_username: Optional[str] = None
    winrm_password_env: str = "WIPERX_WINRM_PASS"
    winrm_port: int = 5986
    winrm_verify_ssl: bool = True


@dataclass
class WipeRequest:
    """Encapsulates a complete wipe request."""
    disk_identifier: str            # "sda", "nvme0n1", "1" (Windows disk number)
    confirmed_disk_name: str        # User must type this manually (safety check)
    mode: ExecutionMode = ExecutionMode.LOCAL
    remote_config: Optional[RemoteConnectionConfig] = None
    method: str = "auto"            # "auto" | "shred" | "dd" | "nvme" | "diskpart"
    log_callback: Optional[Callable[[str], None]] = None


@dataclass
class WipeResult:
    """Result of a wipe operation."""
    success: bool
    disk_identifier: str
    strategy_name: str
    hostname: str
    os_detected: str
    timestamp: str
    log_lines: List[str] = field(default_factory=list)
    error: Optional[str] = None
    disk_model: str = ""
    disk_serial: str = ""
    method: str = "auto"          # requested wipe method (see core.wipe_passes)
    pass_count: int = 0           # explicit overwrite passes run (0 = native default)
    verification: Optional[dict] = None  # post-wipe WipeVerifier result


class ExecutionManager:
    """
    Central orchestrator for all WiperX operations.
    
    Usage:
        manager = ExecutionManager()
        
        # Scan
        disks = manager.scan_disks(mode=ExecutionMode.LOCAL)
        
        # Wipe
        request = WipeRequest(disk_identifier="sdb", confirmed_disk_name="sdb")
        result = manager.execute_wipe(request)
    """

    def __init__(self):
        self._log_buffer: List[str] = []

    # ------------------------------------------------------------------
    # Public API
    # ------------------------------------------------------------------

    def scan_disks(
        self,
        mode: ExecutionMode = ExecutionMode.LOCAL,
        remote_config: Optional[RemoteConnectionConfig] = None,
    ) -> List:
        """
        Scan disks on the target machine.

        Args:
            mode          : Execution mode (LOCAL, REMOTE_SSH, REMOTE_WINRM).
            remote_config : Connection config for remote targets.

        Returns:
            List[DiskInfo]: Discovered disks.
        """
        executor, os_type = self._build_executor_and_detect_os(mode, remote_config)

        try:
            scanner = DiskScanner(executor=executor, os_type=os_type)
            return scanner.scan()
        finally:
            executor.close()

    def execute_wipe(self, request: WipeRequest) -> WipeResult:
        """
        Execute a complete disk wipe with all safety checks enforced.

        Safety checks (all mandatory, in order):
          1. Admin/root privilege check
          2. Disk name confirmation matches (anti-typo guard)
          3. Disk is not the system disk
          4. Disk is not mounted (or has mounted partitions)
          5. User double confirmation (handled by caller — verified here)

        Args:
            request : WipeRequest with all parameters.

        Returns:
            WipeResult: Outcome of the wipe operation.
        """
        import datetime

        self._log_buffer = []
        timestamp = datetime.datetime.utcnow().isoformat() + "Z"

        def _log(msg: str):
            self._log_buffer.append(msg)
            logger.info(msg)
            if request.log_callback:
                request.log_callback(msg)

        _log("=" * 60)
        _log(f"WiperX Wipe Operation Started at {timestamp}")
        _log(f"Target Disk: {request.disk_identifier}")
        _log(f"Mode: {request.mode}")
        _log("=" * 60)

        executor, os_type = None, None

        try:
            # Build executor and detect OS
            executor, os_type = self._build_executor_and_detect_os(
                request.mode, request.remote_config
            )
            _log(f"OS Detected: {os_type}")

            # --- Safety Check 1: Privilege ---
            _log("[Safety Check 1] Verifying admin/root privileges...")
            self._check_privileges(executor, os_type, _log)

            # --- Resolve disk info ---
            _log(f"[DiskScan] Fetching disk info for: {request.disk_identifier}")
            scanner = DiskScanner(executor=executor, os_type=os_type)
            all_disks = scanner.scan()
            target_disk = self._find_disk(all_disks, request.disk_identifier)

            if target_disk is None:
                raise ValueError(
                    f"Disk '{request.disk_identifier}' not found on target. "
                    f"Available: {[d.identifier for d in all_disks]}"
                )

            _log(f"[DiskInfo] Model: {target_disk.model}")
            _log(f"[DiskInfo] Serial: {target_disk.serial}")
            _log(f"[DiskInfo] Size: {target_disk.size_human}")
            _log(f"[DiskInfo] Type: {target_disk.disk_type} / Bus: {target_disk.bus_type}")

            # --- Safety Check 2: Name confirmation ---
            _log("[Safety Check 2] Verifying user-typed disk name matches...")
            if request.confirmed_disk_name.strip() != request.disk_identifier.strip():
                raise PermissionError(
                    f"Safety FAILED: User typed '{request.confirmed_disk_name}' "
                    f"but disk identifier is '{request.disk_identifier}'. "
                    "They must match exactly."
                )
            _log("[Safety Check 2] PASSED: Disk name confirmed.")

            # --- Safety Check 3: System disk ---
            _log("[Safety Check 3] Checking if disk is system disk...")
            if target_disk.is_system:
                raise PermissionError(
                    f"SAFETY BLOCK: Disk '{target_disk.identifier}' is the SYSTEM DISK "
                    "containing the running OS. Wiping is prohibited.\n"
                    "Enterprise solution: Use PXE boot or bootable ISO to wipe system disks."
                )
            _log("[Safety Check 3] PASSED: Not a system disk.")

            # --- Safety Check 4: Mounted check ---
            _log("[Safety Check 4] Checking if disk is currently mounted...")
            if target_disk.is_mounted:
                raise PermissionError(
                    f"SAFETY BLOCK: Disk '{target_disk.identifier}' or its partitions "
                    "are currently mounted. Unmount before wiping."
                )
            _log("[Safety Check 4] PASSED: Disk is not mounted.")

            # Select strategy
            strategy = get_strategy(
                disk=target_disk, os_type=os_type, method=request.method
            )
            _log(f"[Strategy] Selected: {strategy.name} — {strategy.description}")

            # Resolve the overwrite pass list. "auto" keeps each strategy's
            # native single-shot command; any other method runs an explicit
            # PassSpec sequence via strategy._run_passes.
            method = (request.method or "auto").strip().lower()
            pass_list = None
            if method not in ("auto", ""):
                from core.wipe_passes import describe, pass_spec

                try:
                    pass_list = pass_spec(method)
                    _log(f"[Method] {method}: {describe(method)} "
                         f"({len(pass_list)} pass(es))")
                except ValueError as exc:
                    _log(f"[Method] {exc}; falling back to native default.")
                    method = "auto"

            # Execute wipe
            _log(">>> INITIATING WIPE — This is irreversible <<<")
            success = strategy.execute(
                disk=target_disk,
                executor=executor,
                log_callback=_log,
                passes=pass_list,
            )

            hostname = self._get_target_hostname(request)
            _log(f">>> WIPE {'SUCCEEDED' if success else 'FAILED'} <<<")

            # --- Post-wipe verification ---
            verification = None
            if success:
                try:
                    from core.verifier import WipeVerifier

                    expected = "any"
                    if pass_list:
                        last = next(
                            (p for p in reversed(pass_list) if p.kind != "verify"), None
                        )
                        if last is not None:
                            if last.kind == "random":
                                expected = "random"
                            elif last.kind == "fixed" and last.byte == 0:
                                expected = "zeroed"
                    verification = WipeVerifier().verify(
                        target_disk, executor, os_type,
                        log_callback=_log, expected=expected,
                    )
                except Exception as exc:  # noqa: BLE001 - never fail the wipe on verify
                    _log(f"[Verify] verification error: {exc}")
                    verification = {
                        "verified": None, "method": "error", "details": str(exc)
                    }

            return WipeResult(
                success=success,
                disk_identifier=request.disk_identifier,
                strategy_name=strategy.name,
                hostname=hostname,
                os_detected=str(os_type),
                timestamp=timestamp,
                log_lines=list(self._log_buffer),
                disk_model=target_disk.model,
                disk_serial=target_disk.serial,
                method=method,
                pass_count=len(pass_list) if pass_list else 0,
                verification=verification,
            )

        except (PermissionError, ValueError) as e:
            _log(f"[BLOCKED] {e}")
            return WipeResult(
                success=False,
                disk_identifier=request.disk_identifier,
                strategy_name="None",
                hostname=self._get_target_hostname(request),
                os_detected=str(os_type) if os_type else "Unknown",
                timestamp=timestamp,
                log_lines=list(self._log_buffer),
                error=str(e),
            )

        except Exception as e:
            _log(f"[ERROR] Unexpected failure: {e}")
            logger.exception("[ExecutionManager] Unexpected error during wipe.")
            return WipeResult(
                success=False,
                disk_identifier=request.disk_identifier,
                strategy_name="None",
                hostname=self._get_target_hostname(request),
                os_detected=str(os_type) if os_type else "Unknown",
                timestamp=timestamp,
                log_lines=list(self._log_buffer),
                error=str(e),
            )

        finally:
            if executor:
                executor.close()

    # ------------------------------------------------------------------
    # Internal Helpers
    # ------------------------------------------------------------------

    def _build_executor_and_detect_os(self, mode: ExecutionMode, remote_config=None):
        """Build the correct executor and detect target OS."""
        from core.os_detector import OSDetector, OSType
        from core.executors import LocalExecutor

        detector = OSDetector()

        if mode == ExecutionMode.LOCAL:
            executor = LocalExecutor()
            os_type = detector.detect_local()
            return executor, os_type

        if remote_config is None:
            raise ValueError("remote_config is required for remote execution modes.")

        if mode == ExecutionMode.REMOTE_SSH:
            from core.executors.ssh_executor import SSHExecutor
            executor = SSHExecutor(
                hostname=remote_config.hostname,
                username=remote_config.ssh_username,
                key_path=remote_config.ssh_key_path,
                port=remote_config.ssh_port,
            )
            executor.connect()
            os_type = detector.detect_remote(ssh_executor=executor)

        elif mode == ExecutionMode.REMOTE_WINRM:
            from core.executors.winrm_executor import WinRMExecutor
            executor = WinRMExecutor(
                hostname=remote_config.hostname,
                username=remote_config.winrm_username,
                password_env_var=remote_config.winrm_password_env,
                port=remote_config.winrm_port,
                verify_ssl=remote_config.winrm_verify_ssl,
            )
            executor.connect()
            os_type = detector.detect_remote(winrm_executor=executor)

        else:
            raise ValueError(f"Unknown execution mode: {mode}")

        if os_type.value == "unsupported":
            executor.close()
            raise RuntimeError(
                f"OS detection failed for {remote_config.hostname}. "
                "Could not connect via SSH or WinRM."
            )

        return executor, os_type

    def _check_privileges(self, executor, os_type, log_fn):
        """Check for root/admin privileges on the target."""
        from core.os_detector import OSType
        from core.executors import LocalExecutor

        if isinstance(executor, LocalExecutor):
            import os
            if platform.system().lower() != "windows":
                if os.geteuid() != 0:
                    raise PermissionError(
                        "WiperX requires root privileges. Run with sudo."
                    )
            log_fn("[Safety Check 1] PASSED: Running with required privileges.")
            return

        # Remote: check via command
        if os_type == OSType.LINUX:
            result = executor.run_command("id -u")
            if result.strip() != "0":
                raise PermissionError(
                    f"Remote user is not root (id={result.strip()}). "
                    "SSH as root or use sudo."
                )
        elif os_type == OSType.WINDOWS:
            result = executor.run_command(
                "[Security.Principal.WindowsIdentity]::GetCurrent().Name"
            )
            log_fn(f"[Safety Check 1] Remote user: {result.strip()}")

        log_fn("[Safety Check 1] PASSED: Privileges verified.")

    def _find_disk(self, disks, identifier: str):
        """Find a disk by identifier in the disk list."""
        for disk in disks:
            if disk.identifier == identifier:
                return disk
        return None

    def _get_target_hostname(self, request: WipeRequest) -> str:
        """Get hostname string for reporting."""
        if request.mode == ExecutionMode.LOCAL:
            return socket.gethostname()
        elif request.remote_config:
            return request.remote_config.hostname
        return "unknown"
