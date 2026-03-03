#!/usr/bin/env python3
# wiperx/cli/wiperx_cli.py
"""
WiperX CLI
----------
Command-line interface for WiperX disk wiping system.

All wipe logic is delegated to core.ExecutionManager.
The CLI only handles argument parsing, user interaction, and output formatting.

Usage Examples:
    wiperx --local --scan
    wiperx --local --wipe sdb --method secure
    wiperx --remote 192.168.1.10 --scan --ssh-user admin --ssh-key ~/.ssh/id_rsa
    wiperx --remote 192.168.1.10 --wipe sda --method secure --ssh-user admin
    wiperx --remote 192.168.1.20 --wipe 1 --method secure --winrm --winrm-user Administrator
    wiperx --local --wipe sdb --report-pdf
"""

import sys
import os
import getpass
import logging

import click
from colorama import init as colorama_init, Fore, Style
from tabulate import tabulate

# Add project root to path
sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

from core.execution_manager import (
    ExecutionManager,
    ExecutionMode,
    RemoteConnectionConfig,
    WipeRequest,
)

colorama_init(autoreset=True)
logger = logging.getLogger(__name__)


# ---------------------------------------------------------------------------
# CLI Entry Point
# ---------------------------------------------------------------------------

@click.group(invoke_without_command=True)
@click.pass_context
def cli(ctx):
    """
    WiperX — Production-Grade Cross-Platform Disk Wiping System\n
    Use --help on any subcommand for details.
    """
    if ctx.invoked_subcommand is None:
        click.echo(ctx.get_help())


# ---------------------------------------------------------------------------
# SCAN Command
# ---------------------------------------------------------------------------

@cli.command()
@click.option("--local", "mode", flag_value="local", default=True, help="Scan local machine.")
@click.option("--remote", "mode", flag_value="remote", help="Scan remote machine.")
@click.option("--host", default=None, help="Remote hostname or IP.")
@click.option("--ssh-user", default=None, help="SSH username for Linux remote.")
@click.option("--ssh-key", default=None, help="Path to SSH private key.")
@click.option("--ssh-port", default=22, show_default=True, help="SSH port.")
@click.option("--winrm", "use_winrm", is_flag=True, help="Use WinRM (Windows remote).")
@click.option("--winrm-user", default=None, help="WinRM username.")
@click.option("--winrm-port", default=5986, show_default=True, help="WinRM port.")
def scan(mode, host, ssh_user, ssh_key, ssh_port, use_winrm, winrm_user, winrm_port):
    """Scan and list all disks on the target machine."""
    print_banner()
    manager = ExecutionManager()

    exec_mode, remote_config = _resolve_mode(
        mode, host, ssh_user, ssh_key, ssh_port,
        use_winrm, winrm_user, winrm_port
    )

    click.echo(f"{Fore.CYAN}Scanning disks on {_target_label(exec_mode, remote_config)}...{Style.RESET_ALL}\n")

    try:
        disks = manager.scan_disks(mode=exec_mode, remote_config=remote_config)

        if not disks:
            click.echo(f"{Fore.YELLOW}No disks found.{Style.RESET_ALL}")
            return

        _print_disk_table(disks)

    except Exception as e:
        click.echo(f"{Fore.RED}ERROR: {e}{Style.RESET_ALL}", err=True)
        sys.exit(1)


# ---------------------------------------------------------------------------
# WIPE Command
# ---------------------------------------------------------------------------

@cli.command()
@click.argument("disk_identifier")
@click.option("--local", "mode", flag_value="local", default=True, help="Wipe local disk.")
@click.option("--remote", "mode", flag_value="remote", help="Wipe remote disk.")
@click.option("--host", default=None, help="Remote hostname or IP.")
@click.option("--ssh-user", default=None, help="SSH username.")
@click.option("--ssh-key", default=None, help="Path to SSH private key.")
@click.option("--ssh-port", default=22, show_default=True, help="SSH port.")
@click.option("--winrm", "use_winrm", is_flag=True, help="Use WinRM.")
@click.option("--winrm-user", default=None, help="WinRM username.")
@click.option("--winrm-port", default=5986, show_default=True, help="WinRM port.")
@click.option("--method", default="auto", show_default=True,
              type=click.Choice(["auto", "shred", "dd", "nvme", "diskpart"]),
              help="Wipe method override. 'auto' selects based on disk type.")
@click.option("--report-pdf", is_flag=True, help="Generate PDF certificate after wipe.")
@click.option("--operator", default=None, help="Operator name for report.")
def wipe(disk_identifier, mode, host, ssh_user, ssh_key, ssh_port,
         use_winrm, winrm_user, winrm_port, method, report_pdf, operator):
    """
    Wipe a disk. DISK_IDENTIFIER is the disk name (e.g., sdb, nvme0n1, 1).

    \b
    Examples:
        wiperx wipe sdb
        wiperx wipe sdb --remote --host 192.168.1.10 --ssh-user admin
        wiperx wipe 1 --remote --host 192.168.1.20 --winrm --winrm-user Administrator
    """
    print_banner()
    manager = ExecutionManager()

    exec_mode, remote_config = _resolve_mode(
        mode, host, ssh_user, ssh_key, ssh_port,
        use_winrm, winrm_user, winrm_port
    )

    # ── Display target info ──
    target_label = _target_label(exec_mode, remote_config)
    click.echo(f"\n{Fore.YELLOW}{'='*60}")
    click.echo(f"  WiperX Wipe Operation")
    click.echo(f"  Target  : {target_label}")
    click.echo(f"  Disk    : {disk_identifier}")
    click.echo(f"  Method  : {method}")
    click.echo(f"{'='*60}{Style.RESET_ALL}\n")

    # ── Safety: First confirmation ──
    click.echo(
        f"{Fore.RED}WARNING: This will PERMANENTLY and IRREVERSIBLY destroy all data "
        f"on disk '{disk_identifier}'.{Style.RESET_ALL}"
    )
    click.echo("This action CANNOT be undone.\n")

    if not click.confirm(f"Are you sure you want to wipe disk '{disk_identifier}'?", default=False):
        click.echo("Wipe aborted.")
        sys.exit(0)

    # ── Safety: Manual disk name entry ──
    click.echo(f"\n{Fore.YELLOW}SECURITY CHECK: Please type the disk identifier manually to confirm:{Style.RESET_ALL}")
    typed_name = click.prompt(f"Type '{disk_identifier}' to confirm")

    if typed_name.strip() != disk_identifier.strip():
        click.echo(f"{Fore.RED}ERROR: Entered '{typed_name}' but expected '{disk_identifier}'. Aborting.{Style.RESET_ALL}")
        sys.exit(1)

    # ── Safety: Second confirmation ──
    click.echo(f"\n{Fore.RED}FINAL CONFIRMATION:{Style.RESET_ALL}")
    if not click.confirm("Last chance: Proceed with permanent data destruction?", default=False):
        click.echo("Wipe aborted.")
        sys.exit(0)

    # ── Get operator name ──
    if not operator:
        operator = click.prompt("Operator name (for report)", default=getpass.getuser())

    # ── Execute ──
    click.echo(f"\n{Fore.CYAN}Starting wipe...{Style.RESET_ALL}\n")

    def live_log(msg: str):
        """Print log messages in real-time to console."""
        color = Fore.RED if "ERROR" in msg or "BLOCK" in msg else \
                Fore.YELLOW if "WARNING" in msg or "Safety" in msg else \
                Fore.GREEN if "PASSED" in msg or "complete" in msg.lower() else \
                Fore.WHITE
        click.echo(f"{color}{msg}{Style.RESET_ALL}")

    request = WipeRequest(
        disk_identifier=disk_identifier,
        confirmed_disk_name=typed_name,
        mode=exec_mode,
        remote_config=remote_config,
        method=method,
        log_callback=live_log,
    )

    try:
        result = manager.execute_wipe(request)

        click.echo(f"\n{'='*60}")
        if result.success:
            click.echo(f"{Fore.GREEN}✓ WIPE COMPLETED SUCCESSFULLY{Style.RESET_ALL}")
        else:
            click.echo(f"{Fore.RED}✗ WIPE FAILED{Style.RESET_ALL}")
            if result.error:
                click.echo(f"  Reason: {result.error}")
        click.echo(f"{'='*60}\n")

        # ── Generate Reports ──
        from core.report_generator import ReportGenerator
        reporter = ReportGenerator()

        json_path = reporter.generate_json_report(result, operator=operator)
        click.echo(f"{Fore.CYAN}JSON Report: {json_path}{Style.RESET_ALL}")

        if report_pdf:
            pdf_path = reporter.generate_pdf_report(result, operator=operator)
            if pdf_path:
                click.echo(f"{Fore.CYAN}PDF Certificate: {pdf_path}{Style.RESET_ALL}")

        sys.exit(0 if result.success else 1)

    except Exception as e:
        click.echo(f"{Fore.RED}FATAL ERROR: {e}{Style.RESET_ALL}", err=True)
        sys.exit(1)


# ---------------------------------------------------------------------------
# INFO Command
# ---------------------------------------------------------------------------

@cli.command()
def info():
    """Display WiperX system information and available strategies."""
    print_banner()
    click.echo("\nWiperX — Cross-Platform Disk Wiping System")
    click.echo("Version : 1.0.0")
    click.echo("Author  : WiperX Team")
    click.echo("License : MIT\n")

    click.echo("Supported Wipe Strategies:")
    strategies = [
        ["Linux HDD", "GNU shred -n1 -z", "SATA HDD", "NIST SP 800-88"],
        ["Linux SSD", "blkdiscard + dd zero", "SATA SSD", "ATA Secure Erase equivalent"],
        ["Linux NVMe", "nvme format --ses=1", "NVMe SSD", "NVMe Spec Crypto Erase"],
        ["Linux USB", "dd if=/dev/zero", "USB drives", "Full sector overwrite"],
        ["Windows", "diskpart clean all", "All Windows disks", "Microsoft diskpart"],
    ]
    click.echo(tabulate(
        strategies,
        headers=["Strategy", "Command", "Target", "Standard"],
        tablefmt="rounded_outline"
    ))


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def print_banner():
    """Print WiperX ASCII banner."""
    click.echo(f"""
{Fore.RED}
 ██╗    ██╗██╗██████╗ ███████╗██████╗ ██╗  ██╗
 ██║    ██║██║██╔══██╗██╔════╝██╔══██╗╚██╗██╔╝
 ██║ █╗ ██║██║██████╔╝█████╗  ██████╔╝ ╚███╔╝ 
 ██║███╗██║██║██╔═══╝ ██╔══╝  ██╔══██╗ ██╔██╗ 
 ╚███╔███╔╝██║██║     ███████╗██║  ██║██╔╝ ██╗
  ╚══╝╚══╝ ╚═╝╚═╝     ╚══════╝╚═╝  ╚═╝╚═╝  ╚═╝
{Fore.WHITE}  Production-Grade Cross-Platform Disk Wiping
{Style.RESET_ALL}""")


def _resolve_mode(mode, host, ssh_user, ssh_key, ssh_port,
                  use_winrm, winrm_user, winrm_port):
    """
    Resolve execution mode and build RemoteConnectionConfig if needed.
    """
    if mode == "local":
        return ExecutionMode.LOCAL, None

    if not host:
        click.echo(f"{Fore.RED}ERROR: --host is required for remote mode.{Style.RESET_ALL}", err=True)
        sys.exit(1)

    if use_winrm:
        config = RemoteConnectionConfig(
            hostname=host,
            mode=ExecutionMode.REMOTE_WINRM,
            winrm_username=winrm_user,
            winrm_port=winrm_port,
        )
        return ExecutionMode.REMOTE_WINRM, config
    else:
        config = RemoteConnectionConfig(
            hostname=host,
            mode=ExecutionMode.REMOTE_SSH,
            ssh_username=ssh_user,
            ssh_key_path=ssh_key,
            ssh_port=ssh_port,
        )
        return ExecutionMode.REMOTE_SSH, config


def _target_label(exec_mode, remote_config) -> str:
    if exec_mode == ExecutionMode.LOCAL:
        import socket
        return f"LOCAL ({socket.gethostname()})"
    return f"REMOTE ({remote_config.hostname})"


def _print_disk_table(disks):
    """Print disk list as a formatted table."""
    rows = []
    for d in disks:
        system_flag = f"{Fore.RED}[SYSTEM]{Style.RESET_ALL}" if d.is_system else ""
        mounted_flag = f"{Fore.YELLOW}[MOUNTED]{Style.RESET_ALL}" if d.is_mounted else ""
        flags = " ".join(filter(None, [system_flag, mounted_flag]))
        rows.append([
            d.identifier,
            d.model,
            d.serial or "-",
            d.size_human,
            d.disk_type,
            d.bus_type,
            flags or "OK",
        ])

    click.echo(tabulate(
        rows,
        headers=["Identifier", "Model", "Serial", "Size", "Type", "Bus", "Status"],
        tablefmt="rounded_outline",
    ))
    click.echo(f"\n{Fore.YELLOW}NOTE: Disks marked [SYSTEM] or [MOUNTED] cannot be wiped.{Style.RESET_ALL}")


# ---------------------------------------------------------------------------
# Main entry
# ---------------------------------------------------------------------------

if __name__ == "__main__":
    logging.basicConfig(level=logging.WARNING)
    cli()
