# WiperX — Production-Grade Cross-Platform Disk Wiping System

> **Designed for**: Smart India Hackathon · Academic Demonstration · Enterprise PoC · Security Compliance Discussion
>
> Built against **SIH26149** ("Design and Development of an Integrated Secure Data Erasure and Advanced File Recovery Tool for Digital Forensics and Data Sanitization", NTRO, Blockchain & Cybersecurity theme). All three required modules — Secure Drive Eraser, Secure File & Folder Eraser, Advanced File Carving & Recovery — are implemented; see [`docs/SIH26149_GAP_ANALYSIS.md`](docs/SIH26149_GAP_ANALYSIS.md) for the detailed mapping and [`docs/ROADMAP.md`](docs/ROADMAP.md) for what's left.

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
│   ├── entropy.py                 # Sample-entropy verdicts (zeroed/random/live)
│   ├── wipe_passes.py             # Pass tables: Clear/Zero/Random/DoD-3/DoD-7/Gutmann/NIST-Purge
│   ├── report_generator.py        # JSON + PDF report generation
│   ├── report_signer.py           # Ed25519-signed envelope for every report type
│   ├── audit_logger.py            # Structured JSON audit logging
│   ├── strategies/
│   │   └── __init__.py            # All wipe strategies (factory pattern)
│   ├── executors/
│   │   ├── __init__.py            # BaseExecutor + LocalExecutor
│   │   ├── ssh_executor.py        # SSH remote executor (Paramiko)
│   │   └── winrm_executor.py      # WinRM remote executor (pywinrm)
│   ├── eraser_file/                # Module 2: Secure File & Folder Eraser
│   │   ├── service.py             # Orchestrator: shred → free-space clear → certificate
│   │   ├── batch.py                # Batch shred over multiple paths
│   │   ├── file_shredder.py       # Per-file overwrite + zero-rename-delete
│   │   ├── trace_scrubber.py      # Filesystem/metadata trace cleanup
│   │   └── verify.py              # Post-erase verification via filefrag
│   └── recovery/                   # Module 3: Advanced File Carving & Recovery
│       ├── service.py             # Orchestrator: acquire → undelete → carve → classify → report
│       ├── acquire.py             # Read-only source open + hash + case dir
│       ├── fs_recover.py          # Filesystem-aware undelete (pytsk3/Sleuth Kit)
│       ├── signatures.py          # File-type signature table + header-hit scanning
│       ├── carver_header.py       # Signature-based header carving
│       ├── carver_structure.py    # Structure-aware end-of-file refinement
│       ├── carver_fragment.py     # Fragmented/bifragment-gap reconstruction (e.g. JPEG)
│       ├── classify.py            # libmagic-based content classification
│       ├── validate.py            # Structural validity check per file type
│       ├── confidence.py          # Confidence scoring from carve/classify/validate signals
│       └── case_report.py         # Signed forensic case report
│
├── cli/
│   ├── __init__.py
│   └── wiperx_cli.py              # Click-based CLI (no wipe/erase/recovery logic — delegates to core)
│
├── web/
│   ├── __init__.py
│   ├── app.py                     # Flask application factory
│   ├── models.py                  # User model, RBAC, machine registry
│   ├── blueprints/
│   │   ├── __init__.py
│   │   ├── auth.py                # Login/logout
│   │   ├── dashboard.py           # Overview page + unified audit log view
│   │   ├── machines.py            # Remote machine CRUD
│   │   ├── disks.py               # Disk scanning
│   │   ├── wipe.py                # Wipe confirm + SSE streaming
│   │   ├── eraser.py              # File/folder erase (Module 2 UI)
│   │   ├── recovery.py            # Recovery run, live log stream, case browser (Module 3 UI)
│   │   └── reports.py             # Report list + download
│   ├── templates/
│   │   ├── base.html              # Bootstrap dark theme base
│   │   ├── auth/login.html
│   │   ├── dashboard/{index,audit}.html
│   │   ├── machines/{index,add}.html
│   │   ├── disks/scan_results.html
│   │   ├── wipe/{confirm,execute}.html
│   │   ├── eraser/{index,result}.html
│   │   ├── recovery/{index,run,cases,case}.html
│   │   └── reports/{index,view}.html
│   └── static/{css,js}/
│
├── docs/
│   ├── SIH26149_GAP_ANALYSIS.md   # Problem statement vs. implementation, module by module
│   └── ROADMAP.md                 # Verified status + remaining backlog
├── tools/
│   ├── make_demo_image.sh         # Builds a sample disk image for carving demos
│   └── demo_erase.sh              # End-to-end erase demo script
├── reports/                       # Generated reports (JSON + PDF, Ed25519-signed)
├── logs/                          # Audit logs (JSON Lines format)
├── tests/                         # Test suite (81 tests: drive-erase, file-erase, recovery, signing, web)
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
  scan           Scan and list all disks on the target machine.
  wipe           Wipe a disk (DISK_IDENTIFIER = sda, sdb, nvme0n1, 1...)
  erase-file     Securely shred one or more individual files.
  erase-folder   Securely shred a directory tree.
  wipe-free      Overwrite free space on a mount point + fstrim.
  recover        Run recovery/carving against a source image or device.
  verify-report  Verify the Ed25519 signature on a report/certificate.
  info           Display available wipe strategies.

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
  --method [auto|shred|dd|nvme|diskpart|dod|dod-3|dod-7|gutmann|nist-purge]
                        Wipe method / pass table (see Wipe Strategies below)
  --report-pdf         Generate PDF certificate
  --operator TEXT      Operator name for report

erase-file / erase-folder options:
  --passes INT          Random overwrite passes (default: 1)

wipe-free options:
  --passes INT          Random fill passes over free space (default: 1)

recover options:
  --source PATH          Image file or block device to recover from (required)

Examples:
  sudo python -m cli.wiperx_cli erase-file secret.docx --passes 3
  sudo python -m cli.wiperx_cli erase-folder ./old-case-files --passes 3
  sudo python -m cli.wiperx_cli wipe-free /mnt/usb --passes 1
  sudo python -m cli.wiperx_cli recover --source /dev/sdb1
  python -m cli.wiperx_cli verify-report reports/case-20260831.json
```

---

## Flask Web App Usage

| URL                        | Description                                    |
|-----------------------------|------------------------------------------------|
| `/auth/login`               | Login page                                      |
| `/`                          | Dashboard with stats, quick actions, and unified audit log (`/dashboard/audit`) |
| `/machines/`                | Manage remote machines                          |
| `/machines/add`             | Register a new remote machine                   |
| `/disks/scan/local`         | Scan local disks                                |
| `/disks/scan/remote/<id>`   | Scan a registered remote machine                |
| `/wipe/confirm`             | Wipe confirmation (double confirm)              |
| `/wipe/execute`             | Live wipe execution with SSE log stream         |
| `/eraser/`                  | Secure File & Folder Eraser (Module 2)          |
| `/eraser/run`                | Execute an erase run, returns signed certificate |
| `/recovery/`                | Advanced File Carving & Recovery (Module 3)     |
| `/recovery/run`             | Execute a recovery run                          |
| `/recovery/stream/<id>`     | Live SSE log stream for a running recovery      |
| `/recovery/cases/`          | Browse past recovery cases                      |
| `/recovery/case/<name>`     | Case detail: recovered files, confidence scores, signed report |
| `/reports/`                 | View and download wipe/erase/recovery reports   |

---

## Wipe Strategies

| Strategy            | Command                            | Target           | Notes                                          |
|---------------------|------------------------------------|------------------|------------------------------------------------|
| LinuxHDD-Shred      | `shred -v -n 1 -z /dev/sdX`       | SATA HDD         | 1 random pass + zero pass. NIST 800-88 Clear   |
| LinuxSSD-BlkDiscard | `blkdiscard + dd zero`             | SATA SSD         | TRIM + full zero. Use hdparm for full SE       |
| LinuxNVMe-Format    | `nvme format --ses=1`              | NVMe SSD         | Controller-level cryptographic erase           |
| LinuxUSB-DD         | `dd if=/dev/zero of=/dev/sdX bs=1M`| USB drives       | Full sector overwrite                          |
| Windows-DiskPart    | `diskpart clean all`               | Windows all disks| Full zero write; cannot wipe active OS disk   |

### Multi-Pass Modes (`core/wipe_passes.py`)

Selectable via `--method` on top of the device-specific command above:

| Method       | Passes                                          | Standard                        |
|--------------|--------------------------------------------------|----------------------------------|
| `clear` / `auto` | 1 random + 1 zero                            | NIST SP 800-88 Clear             |
| `zero`       | single 0x00                                      | —                                 |
| `random`     | single random                                    | —                                 |
| `dod` / `dod-3` | 0x00, 0xFF, random                            | DoD 5220.22-M (E)                |
| `dod-7`      | 0x00, 0xFF, random, random, 0x00, 0xFF, random  | DoD 5220.22-M (ECE)              |
| `gutmann`    | 4 random + 27 fixed patterns + 4 random (35-pass)| Gutmann                          |
| `nist-purge` | random pass + read-back verify                   | NIST SP 800-88 Purge             |

Post-wipe, `core/entropy.py` samples the wiped region and classifies it `zeroed` / `fixed-fill` / `low-entropy` / `random-or-live` to catch a wipe that silently didn't reach its target.

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

Shipped since the table below was first written: multi-pass DoD/Gutmann/NIST-Purge modes (`core/wipe_passes.py`), tamper-evident report signing (`core/report_signer.py`, Ed25519 rather than HMAC — stronger, and covers wipe/erase/recovery reports uniformly, not just audit logs), and the Secure File & Folder Eraser + Advanced File Carving & Recovery modules themselves. See [`docs/ROADMAP.md`](docs/ROADMAP.md) for current, actively-maintained status. Remaining open items:

| Feature | Priority | Description |
|---------|----------|-------------|
| hdparm ATA Secure Erase | High | True hardware-level SSD erase via hdparm |
| Disk progress bar | Medium | Parse dd status=progress output for real-time % |
| Concurrent wipe | Medium | Thread pool for wiping multiple disks simultaneously |
| Database backend | High | Replace in-memory stores with PostgreSQL |
| LDAP/AD auth | High | Enterprise SSO integration |
| S3 report upload | Medium | Push reports to immutable cloud storage |
| Wipe scheduling | Medium | Schedule future wipes via APScheduler |
| REST API | Medium | Full JSON API for integration with asset management |
| Docker compose | Medium | Containerized deployment with Nginx reverse proxy |
| SIEM integration | High | Direct log forwarding to Splunk/Elastic |
| Disk health pre-check | Low | SMART status verification before wipe |
| User manual / technical docs / performance eval report | High | Formal deliverables required by SIH26149, not yet written |

---

## Compliance Reference

- **NIST SP 800-88 Rev.1** — Guidelines for Media Sanitization (Clear, Purge, Destroy)
- **DoD 5220.22-M** — DoD National Industrial Security Program Operating Manual
- **IEEE 2883-2022** — IEEE Standard for Sanitizing Storage
- **ISO 27001 A.8.3.2** — Disposal of media

---

*WiperX — Built for security compliance, enterprise PoC, and academic demonstration.*
