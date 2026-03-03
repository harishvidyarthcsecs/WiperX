# WiperX — Production-Grade Cross-Platform Disk Wiping System

> **Designed for**: Smart India Hackathon · Academic Demonstration · Enterprise PoC · Security Compliance Discussion

---

## Table of Contents

1. [Project Overview](#project-overview)
2. [Architecture](#architecture)
3. [Project Structure](#project-structure)
4. [Quick Setup](#quick-setup)
5. [CLI Usage](#cli-usage)
6. [Flask Web App Usage](#flask-web-app-usage)
7. [Wipe Strategies](#wipe-strategies)
8. [Security Design](#security-design)
9. [Role-Based Access Control](#role-based-access-control)
10. [Limitations](#limitations)
11. [Enterprise Considerations](#enterprise-considerations)
12. [Future Improvements](#future-improvements)

---

## Project Overview

WiperX is a **unified, modular disk sanitization system** that operates as both a CLI tool and a Flask web application. All wipe logic is centralized in the core engine — neither the CLI nor Flask contains any wipe commands directly.

### Supported Platforms

| OS       | Local | Remote (SSH) | Remote (WinRM) |
|----------|-------|-------------|----------------|
| Linux    | ✅    | ✅           | ❌              |
| Windows  | ✅    | ❌           | ✅              |

---

## Architecture

```
┌─────────────────────────────────────────────────────────────┐
│                    Interfaces (Thin)                         │
│   ┌──────────────────┐       ┌──────────────────────────┐   │
│   │   CLI (Click)    │       │  Flask Web App           │   │
│   │  wiperx_cli.py   │       │  Blueprints: auth,       │   │
│   │  Argument parse  │       │  dashboard, machines,    │   │
│   │  User prompts    │       │  disks, wipe, reports    │   │
│   └────────┬─────────┘       └─────────────┬────────────┘   │
│            │                               │                 │
│            └──────────────┬────────────────┘                 │
│                           ▼                                  │
│            ┌──────────────────────────────┐                  │
│            │     ExecutionManager          │                  │
│            │  (Central Orchestrator)       │                  │
│            │  • Safety checks (4 layers)   │                  │
│            │  • Executor selection         │                  │
│            │  • OS detection               │                  │
│            │  • Strategy selection         │                  │
│            │  • Report generation          │                  │
│            └──┬──────────────────────┬────┘                  │
│               │                      │                       │
│    ┌──────────▼─────────┐  ┌────────▼──────────┐            │
│    │    OS Detector      │  │   Disk Scanner    │            │
│    │  Local: platform    │  │  Linux: lsblk     │            │
│    │  SSH: uname -s      │  │  Windows: Get-Disk│            │
│    │  WinRM: systeminfo  │  └────────────────────┘           │
│    └─────────────────────┘                                   │
│                                                              │
│    ┌──────────────────────────────────────────────────────┐  │
│    │                  Wipe Strategy Layer                  │  │
│    │  LinuxHDD(shred) | LinuxSSD(blkdiscard) |            │  │
│    │  LinuxNVMe(nvme format) | LinuxUSB(dd) |             │  │
│    │  Windows(diskpart clean all)                         │  │
│    └──────────────────────────────────────────────────────┘  │
│                                                              │
│    ┌───────────────┐  ┌──────────────┐  ┌───────────────┐   │
│    │ LocalExecutor │  │ SSHExecutor  │  │ WinRMExecutor │   │
│    │  subprocess   │  │  Paramiko    │  │   pywinrm     │   │
│    └───────────────┘  └──────────────┘  └───────────────┘   │
└─────────────────────────────────────────────────────────────┘
```

---

## Project Structure

```
wiperx/
├── core/                          # Core Engine (no UI dependencies)
│   ├── __init__.py
│   ├── os_detector.py             # OS detection: local + remote
│   ├── disk_scanner.py            # Disk enumeration (lsblk / Get-Disk)
│   ├── execution_manager.py       # Central orchestrator + safety checks
│   ├── verifier.py                # Post-wipe verification
│   ├── report_generator.py        # JSON + PDF report generation
│   ├── audit_logger.py            # Structured JSON audit logging
│   ├── strategies/
│   │   └── __init__.py            # All wipe strategies (factory pattern)
│   └── executors/
│       ├── __init__.py            # BaseExecutor + LocalExecutor
│       ├── ssh_executor.py        # SSH remote executor (Paramiko)
│       └── winrm_executor.py      # WinRM remote executor (pywinrm)
│
├── cli/
│   ├── __init__.py
│   └── wiperx_cli.py              # Click-based CLI (no wipe logic)
│
├── web/
│   ├── __init__.py
│   ├── app.py                     # Flask application factory
│   ├── models.py                  # User model, RBAC, machine registry
│   ├── blueprints/
│   │   ├── __init__.py
│   │   ├── auth.py                # Login/logout
│   │   ├── dashboard.py           # Overview page
│   │   ├── machines.py            # Remote machine CRUD
│   │   ├── disks.py               # Disk scanning
│   │   ├── wipe.py                # Wipe confirm + SSE streaming
│   │   └── reports.py             # Report list + download
│   ├── templates/
│   │   ├── base.html              # Bootstrap dark theme base
│   │   ├── auth/login.html
│   │   ├── dashboard/index.html
│   │   ├── machines/{index,add}.html
│   │   ├── disks/scan_results.html
│   │   ├── wipe/{confirm,execute}.html
│   │   └── reports/{index,view}.html
│   └── static/{css,js}/
│
├── reports/                       # Generated reports (JSON + PDF)
├── logs/                          # Audit logs (JSON Lines format)
├── tests/                         # Test suite
├── run.py                         # Flask entry point
├── setup.py                       # CLI installation
└── requirements.txt
```

---

## Quick Setup

### Prerequisites

- Python 3.10+
- Linux: `shred`, `nvme-cli`, `util-linux` (lsblk) — usually pre-installed
- Windows: PowerShell 5+, diskpart

### Installation

```bash
# 1. Clone the project
git clone https://github.com/yourorg/wiperx
cd wiperx

# 2. Create virtual environment
python -m venv venv
source venv/bin/activate        # Linux/Mac
venv\Scripts\activate           # Windows

# 3. Install dependencies
pip install -r requirements.txt

# 4. (Optional) Install CLI globally
pip install -e .

# 5. Set environment variables
export WIPERX_SECRET_KEY="your-strong-random-key-here"
export WIPERX_SSH_KEY_PATH="/home/user/.ssh/wiperx_key"
# For WinRM targets:
export WIPERX_WINRM_USER="Administrator"
export WIPERX_WINRM_PASS="your-windows-password"
```

### Run Flask Web App

```bash
python run.py --host 127.0.0.1 --port 5000

# Access at http://127.0.0.1:5000
# Default credentials: admin / admin123
```

### Run CLI

```bash
# Scan local disks
sudo python -m cli.wiperx_cli scan --local

# Wipe a specific disk (Linux)
sudo python -m cli.wiperx_cli wipe sdb --local --report-pdf

# Scan remote Linux machine
python -m cli.wiperx_cli scan --remote --host 192.168.1.10 \
    --ssh-user admin --ssh-key ~/.ssh/wiperx_key

# Wipe remote Linux disk
python -m cli.wiperx_cli wipe sdb --remote --host 192.168.1.10 \
    --ssh-user admin --ssh-key ~/.ssh/wiperx_key

# Wipe remote Windows disk
python -m cli.wiperx_cli wipe 1 --remote --host 192.168.1.20 \
    --winrm --winrm-user Administrator
```

---

## CLI Usage

```
Commands:
  scan    Scan and list all disks on the target machine.
  wipe    Wipe a disk (DISK_IDENTIFIER = sda, sdb, nvme0n1, 1...)
  info    Display available wipe strategies.

Scan options:
  --local              Scan local machine (default)
  --remote             Scan remote machine
  --host TEXT          Remote hostname or IP
  --ssh-user TEXT      SSH username
  --ssh-key TEXT       Path to SSH private key
  --ssh-port INT       SSH port (default: 22)
  --winrm              Use WinRM for Windows remote
  --winrm-user TEXT    WinRM username
  --winrm-port INT     WinRM port (default: 5986)

Wipe options (all scan options, plus):
  --method [auto|shred|dd|nvme|diskpart]   Wipe method
  --report-pdf         Generate PDF certificate
  --operator TEXT      Operator name for report
```

---

## Flask Web App Usage

| URL             | Description                              |
|-----------------|------------------------------------------|
| `/auth/login`   | Login page                               |
| `/`             | Dashboard with stats and quick actions   |
| `/machines/`    | Manage remote machines                   |
| `/machines/add` | Register a new remote machine            |
| `/disks/scan/local` | Scan local disks                     |
| `/disks/scan/remote/<id>` | Scan a registered remote machine |
| `/wipe/confirm` | Wipe confirmation (double confirm)       |
| `/wipe/execute` | Live wipe execution with SSE log stream  |
| `/reports/`     | View and download wipe reports           |

---

## Wipe Strategies

| Strategy            | Command                            | Target           | Notes                                          |
|---------------------|------------------------------------|------------------|------------------------------------------------|
| LinuxHDD-Shred      | `shred -v -n 1 -z /dev/sdX`       | SATA HDD         | 1 random pass + zero pass. NIST 800-88 Clear   |
| LinuxSSD-BlkDiscard | `blkdiscard + dd zero`             | SATA SSD         | TRIM + full zero. Use hdparm for full SE       |
| LinuxNVMe-Format    | `nvme format --ses=1`              | NVMe SSD         | Controller-level cryptographic erase           |
| LinuxUSB-DD         | `dd if=/dev/zero of=/dev/sdX bs=1M`| USB drives       | Full sector overwrite                          |
| Windows-DiskPart    | `diskpart clean all`               | Windows all disks| Full zero write; cannot wipe active OS disk   |

### Strategy Auto-Selection Logic

```
OS == WINDOWS     → WindowsWipeStrategy
OS == LINUX:
  bus_type == USB → LinuxUSBWipeStrategy
  disk_type == NVMe → LinuxNVMeWipeStrategy
  disk_type == SSD  → LinuxSSDWipeStrategy
  else (HDD)       → LinuxHDDWipeStrategy
```

---

## Mandatory Safety Checks

All checks are enforced in `ExecutionManager.execute_wipe()` — **not** in CLI or Flask.

1. **Admin/Root Privilege** — `id -u == 0` (Linux) or `IsUserAnAdmin()` (Windows)
2. **Disk Name Confirmation** — User must type the disk identifier manually (anti-typo)
3. **System Disk Protection** — Disks containing the running OS are blocked
4. **Mount Check** — Disks with mounted partitions cannot be wiped
5. **Double Confirmation** — Both CLI and Flask require two separate confirmations

---

## Security Design

### SSH Security
- **Key-based auth only** — password authentication is disabled in SSHExecutor
- Host key verification via known_hosts (AutoAddPolicy only for development)
- `allow_agent=False`, `look_for_keys=False` prevent unintended key use
- All commands logged before and after execution

### WinRM Security
- **HTTPS (port 5986) only** — plain HTTP port 5985 is rejected by design
- Credentials loaded exclusively from environment variables
- SSL certificate verification configurable (disable only in isolated lab)
- All commands logged

### Credential Management
- Zero hardcoded credentials in source code
- All secrets via environment variables: `WIPERX_SECRET_KEY`, `WIPERX_SSH_KEY_PATH`, `WIPERX_WINRM_PASS`, `WIPERX_WINRM_USER`
- In production: integrate with HashiCorp Vault or AWS Secrets Manager

### Audit Logging
- Every command executed is logged to JSON Lines format
- Log file: `logs/wiperx_audit_YYYY-MM-DD.log`
- Fields: timestamp, event, user, PID, hostname, module
- Production: forward to SIEM (Splunk/ELK) and store on WORM storage

---

## Role-Based Access Control

| Permission          | ADMIN | OPERATOR | VIEWER |
|---------------------|-------|----------|--------|
| scan disks          | ✅    | ✅        | ✅     |
| initiate wipe       | ✅    | ✅        | ❌     |
| manage machines     | ✅    | ❌        | ❌     |
| download reports    | ✅    | ✅        | ✅     |
| view audit logs     | ✅    | ❌        | ❌     |

Roles are checked via `current_user.can("action")` in every blueprint route.

---

## Limitations

### Critical: Cannot Wipe Running OS Disk
The most important limitation of any software-based wiper:
- **Linux**: Cannot `shred`/`dd` the mounted root partition (`/dev/sda` if `/` is on it)
- **Windows**: `diskpart clean all` fails on Disk 0 (system disk) while Windows is running

#### Enterprise Solution: PXE Boot / Bootable ISO

For wiping system disks in a production environment:

1. **PXE Boot (Preboot Execution Environment)**
   - Configure a PXE server (TFTP + DHCP) on your network
   - Boot target machine from network into a lightweight Linux live environment
   - Run WiperX core from the live environment — the local disk is no longer the OS disk
   - Tools: DRBL (Diskless Remote Boot for Linux), FOG Project, Netboot.xyz

2. **Bootable USB/ISO**
   - Create a bootable Linux live ISO with WiperX pre-installed
   - Tools: Ubuntu Live, Tails, Parted Magic, custom Alpine ISO
   - Boot from USB → run WiperX → all local disks are available

3. **Windows WinPE**
   - Build a WinPE environment with diskpart + WiperX
   - Deploy via SCCM/MDT or bootable USB
   - Full disk access including System drive

### Other Limitations

| Limitation | Description |
|------------|-------------|
| HDD shred effectiveness | On some HDDs with automatic remapping (bad sectors), shred may not overwrite all data |
| SSD shred ineffectiveness | Shred is unreliable on SSDs/flash due to wear-levelling and FTL; always use manufacturer's secure erase |
| NVMe requires nvme-cli | `nvme format` requires nvme-cli package on the target system |
| WinRM certificate | Production WinRM requires a valid TLS certificate; self-signed requires `verify_ssl=False` |
| No concurrent wipes | Current implementation doesn't support simultaneous wipe of multiple disks |
| No wipe progress % | dd and shred don't easily report percentage to Python; only raw output is streamed |

---

## Future Improvements

| Feature | Priority | Description |
|---------|----------|-------------|
| NIST 800-88 Purge mode | High | Multi-pass DoD 5220.22-M, Gutmann 35-pass |
| hdparm ATA Secure Erase | High | True hardware-level SSD erase via hdparm |
| Disk progress bar | Medium | Parse dd status=progress output for real-time % |
| Concurrent wipe | Medium | Thread pool for wiping multiple disks simultaneously |
| Database backend | High | Replace in-memory stores with PostgreSQL |
| LDAP/AD auth | High | Enterprise SSO integration |
| S3 report upload | Medium | Push reports to immutable cloud storage |
| HMAC log signing | High | Tamper-evidence for audit logs |
| Wipe scheduling | Medium | Schedule future wipes via APScheduler |
| REST API | Medium | Full JSON API for integration with asset management |
| Docker compose | Medium | Containerized deployment with Nginx reverse proxy |
| SIEM integration | High | Direct log forwarding to Splunk/Elastic |
| Disk health pre-check | Low | SMART status verification before wipe |
| Certificate signing | High | Digital signature on PDF certificates |

---

## Compliance Reference

- **NIST SP 800-88 Rev.1** — Guidelines for Media Sanitization (Clear, Purge, Destroy)
- **DoD 5220.22-M** — DoD National Industrial Security Program Operating Manual
- **IEEE 2883-2022** — IEEE Standard for Sanitizing Storage
- **ISO 27001 A.8.3.2** — Disposal of media

---

*WiperX — Built for security compliance, enterprise PoC, and academic demonstration.*
