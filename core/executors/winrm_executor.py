# wiperx/core/executors/winrm_executor.py
"""
WinRM Executor
--------------
Executes PowerShell commands on a remote Windows host via WinRM over HTTPS.

Security Requirements:
  - HTTPS transport ONLY (port 5986). Plain HTTP (5985) is rejected.
  - Credentials loaded from environment variables — never hardcoded.
  - Certificate verification configurable (disable only in isolated lab envs).
  - All commands are logged for audit.

WinRM Setup on Target (run as Administrator):
    winrm quickconfig
    winrm set winrm/config/listener?Address=*+Transport=HTTPS @{CertificateThumbprint="<thumbprint>"}
    netsh advfirewall firewall add rule name="WinRM HTTPS" protocol=TCP dir=in localport=5986 action=allow

Usage:
    executor = WinRMExecutor(
        hostname="192.168.1.20",
        username="Administrator",
        password_env_var="WIPERX_WINRM_PASS"
    )
    output = executor.run_command("Get-Disk")
    executor.close()
"""

import logging
import os
from typing import Optional

logger = logging.getLogger(__name__)

try:
    import winrm
    WINRM_AVAILABLE = True
except ImportError:
    WINRM_AVAILABLE = False
    logger.warning("[WinRMExecutor] pywinrm not installed. WinRM executor unavailable.")

from core.executors import BaseExecutor


class WinRMExecutor(BaseExecutor):
    """
    WinRM-based remote executor for Windows targets.

    Enforces HTTPS transport and loads credentials from environment variables.
    Supports PowerShell commands natively.
    """

    DEFAULT_PORT = 5986  # HTTPS WinRM port
    DEFAULT_TIMEOUT = 60  # seconds

    def __init__(
        self,
        hostname: str,
        username: Optional[str] = None,
        password: Optional[str] = None,
        password_env_var: str = "WIPERX_WINRM_PASS",
        username_env_var: str = "WIPERX_WINRM_USER",
        port: int = DEFAULT_PORT,
        verify_ssl: bool = True,
    ):
        """
        Initialize WinRM executor.

        Args:
            hostname         : Remote Windows host IP or FQDN.
            username         : WinRM username. Falls back to env var.
            password         : WinRM password. Falls back to env var.
            password_env_var : Env var name for password (default: WIPERX_WINRM_PASS).
            username_env_var : Env var name for username (default: WIPERX_WINRM_USER).
            port             : WinRM port. Default 5986 (HTTPS).
            verify_ssl       : Whether to verify SSL certificate.
                               Set False ONLY in isolated lab environments.
        """
        if not WINRM_AVAILABLE:
            raise ImportError(
                "pywinrm is required for WinRM execution. "
                "Install with: pip install pywinrm"
            )

        self.hostname = hostname
        self.port = port
        self.verify_ssl = verify_ssl

        # Load credentials from arguments → environment variables
        self.username = username or os.environ.get(username_env_var)
        self.password = password or os.environ.get(password_env_var)

        if not self.username:
            raise ValueError(
                f"WinRM username not provided. "
                f"Set {username_env_var} environment variable or pass username argument."
            )
        if not self.password:
            raise ValueError(
                f"WinRM password not provided. "
                f"Set {password_env_var} environment variable or pass password argument.\n"
                "SECURITY NOTE: Never hardcode credentials. Use env vars or a secrets manager."
            )

        self._session: Optional["winrm.Session"] = None

    def connect(self) -> None:
        """
        Initialize a WinRM session.
        Sessions are stateless in pywinrm; this creates the session object.
        """
        transport_url = f"https://{self.hostname}:{self.port}/wsman"
        logger.info(
            f"[WinRMExecutor] Initializing session to {self.username}@{self.hostname}:{self.port} "
            f"(HTTPS, SSL verify={self.verify_ssl})"
        )

        server_cert_validation = "validate" if self.verify_ssl else "ignore"

        self._session = winrm.Session(
            target=transport_url,
            auth=(self.username, self.password),
            transport="ssl",
            server_cert_validation=server_cert_validation,
        )
        logger.info(f"[WinRMExecutor] Session created for {self.hostname}")

    def run_command(self, command: str, timeout: int = 120) -> str:
        """
        Execute a PowerShell command on the remote Windows host.

        Args:
            command : PowerShell command string.
            timeout : Execution timeout (note: pywinrm handles this at protocol level).

        Returns:
            str: stdout output from the remote command.

        Raises:
            RuntimeError: If command fails or session is not initialized.
        """
        if self._session is None:
            self.connect()

        logger.info(f"[WinRMExecutor] [{self.hostname}] Running: {command}")

        try:
            result = self._session.run_ps(command)

            if result.status_code != 0:
                error_msg = result.std_err.decode("utf-8", errors="replace").strip()
                logger.error(
                    f"[WinRMExecutor] Command failed (code {result.status_code}): {error_msg}"
                )
                raise RuntimeError(
                    f"WinRM command failed (exit {result.status_code}): {error_msg}"
                )

            output = result.std_out.decode("utf-8", errors="replace").strip()
            logger.debug(f"[WinRMExecutor] Output: {output[:200]}...")
            return output

        except winrm.exceptions.WinRMTransportError as e:
            logger.error(f"[WinRMExecutor] Transport error: {e}")
            raise RuntimeError(f"WinRM transport error: {e}")

        except Exception as e:
            logger.error(f"[WinRMExecutor] Error running command on {self.hostname}: {e}")
            raise

    def test_connection(self) -> bool:
        """
        Test WinRM connectivity by running a benign PowerShell command.

        Returns:
            bool: True if connection and command succeeded.
        """
        try:
            result = self.run_command("Write-Output 'wiperx_test'")
            return "wiperx_test" in result
        except Exception as e:
            logger.warning(f"[WinRMExecutor] Connection test failed: {e}")
            return False

    def close(self) -> None:
        """WinRM sessions are stateless; this clears the session reference."""
        self._session = None
        logger.info(f"[WinRMExecutor] Session to {self.hostname} cleared.")

    def __enter__(self):
        self.connect()
        return self

    def __exit__(self, exc_type, exc_val, exc_tb):
        self.close()
