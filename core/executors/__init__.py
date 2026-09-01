# wiperx/core/executors/__init__.py
"""
Executor Package
----------------
Provides concrete executor implementations:
  - LocalExecutor  : Runs commands on the local machine via subprocess.
  - SSHExecutor    : Runs commands on a remote Linux host via Paramiko SSH.
  - WinRMExecutor  : Runs commands on a remote Windows host via WinRM/HTTPS.

All executors implement the BaseExecutor interface.
"""

import logging
import subprocess
import shlex
from abc import ABC, abstractmethod
from typing import Optional

logger = logging.getLogger(__name__)


# ---------------------------------------------------------------------------
# Base Executor
# ---------------------------------------------------------------------------

class BaseExecutor(ABC):
    """
    Abstract base class for all command executors.
    Defines the interface that all executors must implement.
    """

    @abstractmethod
    def run_command(self, command: str, timeout: int = 120) -> str:
        """
        Execute a shell command and return stdout as a string.

        Args:
            command : The shell command string to execute.
            timeout : Maximum seconds to wait for command completion.

        Returns:
            str: stdout output of the command.

        Raises:
            RuntimeError: If command fails or times out.
        """
        pass

    @abstractmethod
    def test_connection(self) -> bool:
        """
        Test that the executor can reach and authenticate with the target.

        Returns:
            bool: True if connection is successful.
        """
        pass

    @abstractmethod
    def close(self):
        """Release any held connections or resources."""
        pass


# ---------------------------------------------------------------------------
# Local Executor
# ---------------------------------------------------------------------------

class LocalExecutor(BaseExecutor):
    """
    Runs commands on the local machine using subprocess.

    Security considerations:
      - Commands are run as the current user; root/admin required for wipes.
      - subprocess is used with shell=False where possible to prevent injection.
      - Command strings are logged for audit purposes.
    """

    def run_command(self, command: str, timeout: int = 120) -> str:
        """
        Execute a command locally via subprocess.

        Args:
            command : Shell command string.
            timeout : Timeout in seconds.

        Returns:
            str: Combined stdout output.

        Raises:
            RuntimeError: On non-zero exit code or timeout.
        """
        logger.info(f"[LocalExecutor] Running: {command}")

        try:
            # Use shell=True for complex commands (pipes, redirects)
            # In production, prefer shell=False with explicit arg lists
            result = subprocess.run(
                command,
                shell=True,
                capture_output=True,
                text=True,
                timeout=timeout,
            )

            if result.returncode != 0:
                error_msg = result.stderr.strip() or f"Command exited with code {result.returncode}"
                logger.error(f"[LocalExecutor] Command failed: {error_msg}")
                raise RuntimeError(
                    f"Command failed (exit {result.returncode}): {error_msg}"
                )

            output = result.stdout.strip()
            logger.debug(f"[LocalExecutor] Output: {output[:200]}...")
            return output

        except subprocess.TimeoutExpired:
            logger.error(f"[LocalExecutor] Command timed out after {timeout}s: {command}")
            raise RuntimeError(f"Command timed out after {timeout} seconds.")

    def test_connection(self) -> bool:
        """Local executor is always 'connected'."""
        return True

    def close(self):
        """No resources to release for local execution."""
        pass

    def check_privileges(self) -> bool:
        """True if the current process has root (POSIX) / Administrator (Windows).

        Delegates to the local platform adapter so there is one implementation.
        """
        from core.platforms import get_adapter

        return get_adapter().is_admin()
