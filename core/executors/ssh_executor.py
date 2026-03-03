# wiperx/core/executors/ssh_executor.py
"""
SSH Executor
------------
Executes commands on a remote Linux host via SSH using Paramiko.

Security Requirements:
  - Key-based authentication ONLY (no password auth).
  - Host key verification enabled (known_hosts).
  - Connection details loaded from environment variables or config file.
  - Credentials are NEVER hardcoded.

Usage:
    executor = SSHExecutor(
        hostname="192.168.1.10",
        username="admin",
        key_path="/home/user/.ssh/wiperx_key"
    )
    executor.connect()
    output = executor.run_command("uname -a")
    executor.close()
"""

import logging
import os
from typing import Optional

logger = logging.getLogger(__name__)

try:
    import paramiko
    PARAMIKO_AVAILABLE = True
except ImportError:
    PARAMIKO_AVAILABLE = False
    logger.warning("[SSHExecutor] paramiko not installed. SSH executor unavailable.")

from core.executors import BaseExecutor


class SSHExecutor(BaseExecutor):
    """
    SSH-based remote executor for Linux targets.

    Enforces:
      - Key-based authentication only
      - Configurable timeout
      - Full command logging
      - Graceful connection handling
    """

    DEFAULT_PORT = 22
    DEFAULT_TIMEOUT = 30  # seconds for connection
    COMMAND_BUFFER_SIZE = 65536

    def __init__(
        self,
        hostname: str,
        username: str,
        key_path: Optional[str] = None,
        port: int = DEFAULT_PORT,
        known_hosts_path: Optional[str] = None,
    ):
        """
        Initialize SSH executor.

        Args:
            hostname         : Remote host IP or FQDN.
            username         : SSH username.
            key_path         : Path to private key file (required).
                               Falls back to SSH_KEY_PATH env var.
            port             : SSH port (default 22).
            known_hosts_path : Path to known_hosts file for host verification.
        """
        if not PARAMIKO_AVAILABLE:
            raise ImportError(
                "paramiko is required for SSH execution. "
                "Install with: pip install paramiko"
            )

        self.hostname = hostname
        self.username = username
        self.port = port
        self._client: Optional["paramiko.SSHClient"] = None

        # Resolve key path: argument → env var → default
        self.key_path = (
            key_path
            or os.environ.get("WIPERX_SSH_KEY_PATH")
            or os.path.expanduser("~/.ssh/id_rsa")
        )

        self.known_hosts_path = (
            known_hosts_path
            or os.environ.get("WIPERX_KNOWN_HOSTS")
            or os.path.expanduser("~/.ssh/known_hosts")
        )

        if not os.path.isfile(self.key_path):
            raise FileNotFoundError(
                f"SSH private key not found at: {self.key_path}\n"
                "Set WIPERX_SSH_KEY_PATH environment variable or pass key_path argument."
            )

    def connect(self) -> None:
        """
        Establish SSH connection to the remote host.
        MUST be called before run_command().

        Raises:
            paramiko.AuthenticationException: On auth failure.
            paramiko.SSHException: On connection error.
            TimeoutError: If connection times out.
        """
        logger.info(
            f"[SSHExecutor] Connecting to {self.username}@{self.hostname}:{self.port} "
            f"using key: {self.key_path}"
        )

        self._client = paramiko.SSHClient()

        # Load known hosts for host key verification
        if os.path.isfile(self.known_hosts_path):
            self._client.load_host_keys(self.known_hosts_path)
            self._client.set_missing_host_key_policy(paramiko.RejectPolicy())
            logger.info(f"[SSHExecutor] Loaded known hosts from {self.known_hosts_path}")
        else:
            # SECURITY WARNING: AutoAdd is insecure in production.
            # For enterprise use, always pre-populate known_hosts.
            logger.warning(
                "[SSHExecutor] known_hosts not found. "
                "Using AutoAddPolicy — NOT recommended for production."
            )
            self._client.set_missing_host_key_policy(paramiko.AutoAddPolicy())

        try:
            self._client.connect(
                hostname=self.hostname,
                port=self.port,
                username=self.username,
                key_filename=self.key_path,
                timeout=self.DEFAULT_TIMEOUT,
                allow_agent=False,           # Disable SSH agent for security
                look_for_keys=False,         # Only use specified key
            )
            logger.info(f"[SSHExecutor] Connected to {self.hostname}")

        except paramiko.AuthenticationException as e:
            logger.error(f"[SSHExecutor] Authentication failed for {self.username}@{self.hostname}")
            raise

        except Exception as e:
            logger.error(f"[SSHExecutor] Connection failed to {self.hostname}: {e}")
            raise

    def run_command(self, command: str, timeout: int = 120) -> str:
        """
        Execute a command on the remote Linux host.

        Args:
            command : Shell command string.
            timeout : Command execution timeout in seconds.

        Returns:
            str: stdout output from the remote command.

        Raises:
            RuntimeError: If command fails or executor is not connected.
        """
        if self._client is None:
            raise RuntimeError(
                "[SSHExecutor] Not connected. Call connect() before run_command()."
            )

        logger.info(f"[SSHExecutor] [{self.hostname}] Running: {command}")

        try:
            stdin, stdout, stderr = self._client.exec_command(
                command,
                timeout=timeout,
                get_pty=True  # Pseudo-TTY for interactive command output
            )

            # Read output
            output = stdout.read(self.COMMAND_BUFFER_SIZE).decode("utf-8", errors="replace")
            error_output = stderr.read(self.COMMAND_BUFFER_SIZE).decode("utf-8", errors="replace")
            exit_code = stdout.channel.recv_exit_status()

            if exit_code != 0:
                logger.error(
                    f"[SSHExecutor] Command failed (exit {exit_code}): {error_output.strip()}"
                )
                raise RuntimeError(
                    f"Remote command failed (exit {exit_code}): "
                    f"{error_output.strip() or output.strip()}"
                )

            logger.debug(f"[SSHExecutor] Output: {output[:200]}...")
            return output.strip()

        except Exception as e:
            logger.error(f"[SSHExecutor] Error running command on {self.hostname}: {e}")
            raise

    def test_connection(self) -> bool:
        """
        Test SSH connectivity by running a benign command.

        Returns:
            bool: True if connection and command succeeded.
        """
        try:
            self.connect()
            result = self.run_command("echo wiperx_test")
            return "wiperx_test" in result
        except Exception as e:
            logger.warning(f"[SSHExecutor] Connection test failed: {e}")
            return False

    def close(self) -> None:
        """Close the SSH connection and release resources."""
        if self._client:
            self._client.close()
            self._client = None
            logger.info(f"[SSHExecutor] Connection to {self.hostname} closed.")

    def __enter__(self):
        self.connect()
        return self

    def __exit__(self, exc_type, exc_val, exc_tb):
        self.close()
