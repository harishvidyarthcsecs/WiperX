# wiperx/core/os_detector.py
"""
OS Detection Layer
-----------------
Detects the operating system for both local and remote targets.

Local  : Uses Python's `platform` module.
Remote : SSH → runs `uname -s` (Linux/macOS)
         WinRM → runs `systeminfo` (Windows)
         If both fail → marks target as UNSUPPORTED.
"""

import platform
import logging
from enum import Enum
from typing import Optional

logger = logging.getLogger(__name__)


class OSType(str, Enum):
    LINUX = "linux"
    WINDOWS = "windows"
    UNSUPPORTED = "unsupported"


class OSDetector:
    """
    Detects the operating system of a local or remote target.
    Designed to be instantiated per-target.
    """

    def detect_local(self) -> OSType:
        """
        Detect OS of the local machine using platform module.

        Returns:
            OSType: Detected OS type.
        """
        system = platform.system().lower()
        logger.info(f"[OSDetector] Local OS detected: {system}")

        if "linux" in system:
            return OSType.LINUX
        elif "windows" in system:
            return OSType.WINDOWS
        else:
            logger.warning(f"[OSDetector] Unsupported local OS: {system}")
            return OSType.UNSUPPORTED

    def detect_remote(
        self,
        ssh_executor=None,
        winrm_executor=None
    ) -> OSType:
        """
        Detect OS of a remote machine by attempting SSH then WinRM.

        Strategy:
          1. Try SSH → run `uname -s` → if response contains "Linux" → LINUX
          2. Try WinRM → run `systeminfo` → if response succeeds → WINDOWS
          3. If both fail → UNSUPPORTED

        Args:
            ssh_executor:   An initialized SSHExecutor instance (optional).
            winrm_executor: An initialized WinRMExecutor instance (optional).

        Returns:
            OSType: Detected remote OS type.
        """
        # --- Attempt 1: SSH (Linux) ---
        if ssh_executor is not None:
            try:
                result = ssh_executor.run_command("uname -s")
                if result and "linux" in result.strip().lower():
                    logger.info("[OSDetector] Remote OS detected via SSH: LINUX")
                    return OSType.LINUX
                elif result:
                    # Could be macOS or BSD — treat as unsupported in this context
                    logger.warning(
                        f"[OSDetector] SSH uname returned unexpected value: {result}"
                    )
            except Exception as e:
                logger.debug(f"[OSDetector] SSH detection failed: {e}")

        # --- Attempt 2: WinRM (Windows) ---
        if winrm_executor is not None:
            try:
                result = winrm_executor.run_command("systeminfo")
                if result and len(result.strip()) > 0:
                    logger.info("[OSDetector] Remote OS detected via WinRM: WINDOWS")
                    return OSType.WINDOWS
            except Exception as e:
                logger.debug(f"[OSDetector] WinRM detection failed: {e}")

        # --- Both failed ---
        logger.error(
            "[OSDetector] Could not detect remote OS via SSH or WinRM. "
            "Marking as UNSUPPORTED."
        )
        return OSType.UNSUPPORTED

    def get_os_info(self) -> dict:
        """
        Collect detailed local OS information for reporting.

        Returns:
            dict: OS details including version, architecture, hostname.
        """
        return {
            "os_type": platform.system(),
            "os_version": platform.version(),
            "os_release": platform.release(),
            "architecture": platform.machine(),
            "hostname": platform.node(),
            "python_version": platform.python_version(),
        }
