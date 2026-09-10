# WiperX — Production-Grade Cross-Platform Disk Wiping System

[![CI](https://github.com/harishvidyarthcsecs/WiperX/actions/workflows/ci.yml/badge.svg)](https://github.com/harishvidyarthcsecs/WiperX/actions/workflows/ci.yml)
[![License: MIT](https://img.shields.io/badge/license-MIT-blue.svg)](LICENSE)
[![Python 3.10+](https://img.shields.io/badge/python-3.10%2B-blue.svg)](https://www.python.org/downloads/)

> **Designed for**: Smart India Hackathon · Academic Demonstration · Enterprise PoC · Security Compliance Discussion

---

## Table of Contents

1. [Project Overview](#project-overview)
2. [Architecture](#architecture)
3. [Project Structure](#project-structure)
4. [Installation](#installation)
5. [CLI Usage](#cli-usage)
6. [Flask Web App Usage](#flask-web-app-usage)
7. [Wipe Strategies](#wipe-strategies)
8. [Mandatory Safety Checks](#mandatory-safety-checks)
9. [Security Design](#security-design)
10. [Role-Based Access Control](#role-based-access-control)
11. [Testing & CI](#testing--ci)
12. [Limitations](#limitations)
13. [Future Improvements](#future-improvements)
14. [Compliance Reference](#compliance-reference)
15. [License](#license)

---

## Project Overview

WiperX is a **unified, modular disk sanitization system** that operates as both a CLI tool and a Flask web application. All wipe logic is centralized in the core engine — neither the CLI nor Flask contains any wipe commands directly.

Beyond disk wiping, WiperX ships two further modules built on the same execution/reporting engine:

- **Module 2 — Secure File & Folder Eraser**: multi-pass shredding of individual files/folders and free-space wiping, for when you need to destroy specific data without touching the whole disk.
- **Module 3 — Forensic Recovery & Carving**: read-only recovery of deleted/lost files from a device or disk image (filesystem undelete + signature carving), used to *verify* that a wipe actually worked.

Every operation — wipe, erase, or recovery — produces a JSON report, and reports can be Ed25519-signed and independently verified (`wiperx verify-report`).

### Supported Platforms

| OS       | Local | Remote (SSH) | Remote (WinRM) | Wipe backend |
|----------|-------|--------------|----------------|--------------|
| Linux    | ✅    | ✅           | ❌             | `shred` / `blkdiscard` / `nvme format` / `dd` |
| Windows  | ✅    | ❌           | ✅             | `diskpart clean all` |
| macOS    | ✅    | ✅           | ❌             | `diskutil secureErase` / raw `dd` to `/dev/rdiskN` |

On macOS an Apple-silicon **internal** SSD is refused for a sector overwrite
(use *Erase All Content and Settings* — hardware crypto-erase); external
USB / Thunderbolt disks and single partitions (`disk8s1`) are wipeable.

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
│   ├── report_signer.py           # Ed25519 report signing/verification
│   ├── wipe_passes.py             # Overwrite pass tables (--method definitions)
│   ├── audit_logger.py            # Structured JSON audit logging
│   ├── strategies/
│   │   └── __init__.py            # All wipe strategies (factory pattern)
│   ├── executors/
│   │   ├── __init__.py            # BaseExecutor + LocalExecutor
│   │   ├── ssh_executor.py        # SSH remote executor (Paramiko)
│   │   └── winrm_executor.py      # WinRM remote executor (pywinrm)
│   ├── eraser_file/                # Module 2: secure file/folder eraser
│   │   ├── service.py
│   │   └── trace_scrubber.py
│   └── recovery/                  # Module 3: forensic carving/recovery
│       ├── service.py
│       ├── acquire.py             # Raw device/image acquisition
│       ├── carver_header.py
│       ├── carver_fragment.py
│       └── signatures.py
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
├── tools/                         # Standalone scripts/utilities
├── keys/                          # Ed25519 report-signing keypair (local, gitignored)
├── reports/                       # Generated reports (JSON + PDF)
├── logs/                          # Audit logs (JSON Lines format)
├── tests/                         # Test suite (pytest)
├── run.py                         # Flask entry point
├── setup.py                       # CLI installation + console_script entry point
├── requirements.txt               # Runtime dependencies
├── requirements-dev.txt           # pytest / black / flake8
├── WIPERX_ANALYSIS_REPORT.md      # Dated test/validation log across all 3 modules
└── LICENSE
```

---

## Installation

### Prerequisites

- Python 3.10+
- Linux: `shred`, `nvme-cli`, `util-linux` (lsblk) — usually pre-installed
- Windows: PowerShell 5+, diskpart
- macOS: `diskutil` (built-in); optionally `brew install sleuthkit libmagic` for Module 3 recovery

### 1. Clone the repository

```bash
git clone https://github.com/harishvidyarthcsecs/WiperX
cd WiperX
```

### 2. Create a virtual environment

```bash
python3 -m venv .venv
source .venv/bin/activate        # Linux/macOS
.venv\Scripts\activate           # Windows
```

### 3. Install dependencies

```bash
pip install -r requirements.txt

# Recommended: editable install also registers the `wiperx` console command
# (see CLI Usage below) instead of only `python3 -m cli.wiperx_cli`.
pip install -e .

# Optional extras (from setup.py's extras_require):
pip install -e ".[forensics]"        # Module 3 recovery/carving — also needs
                                      # system libmagic + sleuthkit (see Prerequisites)
pip install -e ".[remote-windows]"   # WinRM support for remote Windows targets
pip install -e ".[dev]"              # pytest, black, flake8 — for running tests/CI locally
```

> If you hit `ModuleNotFoundError: No module named 'colorama'` (or any other
> dependency) after activating `.venv`, it usually means `pip install -r
> requirements.txt` was never run against *that* interpreter — re-run step 3.
> Also note: running a command with `sudo` resets `PATH` on most systems, so
> `sudo python3 ...` can silently fall back to the *system* Python instead of
> your `.venv`. Use `sudo .venv/bin/python3 -m cli.wiperx_cli ...` (or
> `sudo $(which wiperx) ...` after an editable install) to keep sudo pointed
> at the venv interpreter.

### 4. Configure environment variables

```bash
cp .env.example .env   # then edit .env with your values
```

| Variable | Required? | Purpose |
|----------|-----------|---------|
| `WIPERX_SECRET_KEY` | **Yes**, unless the web app is started with `--debug` | Flask session signing key |
| `WIPERX_ADMIN_PASSWORD` | No | Sets the demo admin account's password; a random one is generated and logged if unset |
| `WIPERX_SSH_KEY_PATH` | No | Default SSH private key for remote Linux targets |
| `WIPERX_WINRM_USER` / `WIPERX_WINRM_PASS` | No | Credentials for remote Windows (WinRM) targets |
| `WIPERX_VERIFY_PUBKEY` | No | Trust anchor for `wiperx verify-report` |

**No other `export` is required.** In particular:
- **No `PYTHONPATH`** — both `cli/wiperx_cli.py` and `run.py` insert the repo root onto `sys.path` themselves at the top of the file, so `python3 -m cli.wiperx_cli ...` and `python run.py ...` work standalone from the repo root with a plain `pip install -r requirements.txt`.
- **No `FLASK_APP`** — the web app is started with `python run.py`, not `flask run`, so that variable is never read.

---

## CLI Usage

After `pip install -e .` the `wiperx` command is on your `PATH`; without it, substitute `python3 -m cli.wiperx_cli` for `wiperx` in every example below — both forms are equivalent.

`scan` and `wipe` on **local** disks require root/admin (enforced in `core/execution_manager.py`, not just a suggestion — the CLI will refuse to run without it). Remote SSH/WinRM operations do **not** need local root; the remote host authenticates with its own credentials instead.

### `scan` — list disks on a machine

```bash
sudo wiperx scan --local
wiperx scan --remote --host 192.168.1.10 --ssh-user admin --ssh-key ~/.ssh/wiperx_key
```

### `wipe` — permanently erase a disk or partition

```bash
sudo wiperx wipe sdb --local --method dod-3 --report-pdf
wiperx wipe disk8s1 --local --force-unmount        # macOS: just that partition
wiperx wipe sdb --remote --host 192.168.1.10 --ssh-user admin --ssh-key ~/.ssh/wiperx_key
wiperx wipe 1 --remote --host 192.168.1.20 --winrm --winrm-user Administrator
```

Options: `--local` / `--remote --host ... [--ssh-user --ssh-key --ssh-port | --winrm --winrm-user --winrm-port]`, `--method {auto,clear,zero,random,dod,dod-3,dod-7,gutmann,nist-purge}` (see [Wipe Strategies](#wipe-strategies)), `--report-pdf`, `--force-unmount`, `--operator`.

### `erase-file` / `erase-folder` — secure delete (Module 2)

```bash
wiperx erase-file ./secret.docx ./notes.txt --passes 3
wiperx erase-folder ./old-project --passes 3 --wipe-free /mnt/data --fstrim
```

Multi-pass overwrite + rename-before-unlink for individual files or whole directory trees; `erase-folder` can optionally wipe the filesystem's free space afterward.

### `wipe-free` — overwrite free space only

```bash
wiperx wipe-free /mnt/data --passes 2 --fstrim
```

Fills all free space on the filesystem hosting `MOUNT_POINT` to destroy remnants of previously (plain) deleted files.

### `recover` — forensic recovery/carving (Module 3)

```bash
wiperx recover --source /dev/sdb1 --out ./case001
wiperx recover --source ./image.dd --out ./case001 --carve-only
```

Read-only recovery of deleted/lost files via filesystem undelete plus signature-based carving; refuses to run against a mounted read-write source unless `--allow-mounted` is passed.

### `verify-report` — check a signed report/certificate

```bash
wiperx verify-report ./reports/wipe_2026-09-05.json
```

Verifies the Ed25519 signature produced by a `wipe`, `erase-*`, or `recover` run.

### `info` — list strategies and wipe methods

```bash
wiperx info
```

---

## Flask Web App Usage

```bash
export WIPERX_SECRET_KEY="$(python -c 'import secrets;print(secrets.token_hex(32))')"
export WIPERX_ADMIN_PASSWORD="choose-a-password"   # or let it print a random one
python run.py --host 127.0.0.1 --port 5000         # add --debug to skip the secret-key check

# Access at http://127.0.0.1:5000
```

Users: `admin` / `operator` / `viewer` — passwords come from `WIPERX_*_PASSWORD` env vars (a random one is generated and logged if unset). The in-memory store is demo-only; back it with a real database for anything beyond a lab.

### Running the web GUI with root (local disk scan / wipe)

Just like the CLI, **scanning or wiping a local disk from the web GUI needs
root/admin** — the privilege check lives in `core/execution_manager.py`, so the
Flask process itself must run as root. `sudo` resets `PATH` **and** drops most
environment variables, so a bare `sudo python run.py` will use the system Python
and lose `WIPERX_SECRET_KEY`. Use `sudo -E` and point at the venv interpreter:

```bash
# Linux / macOS — keep the exported WIPERX_* vars, use the venv Python
export WIPERX_SECRET_KEY="$(python -c 'import secrets;print(secrets.token_hex(32))')"
export WIPERX_ADMIN_PASSWORD="choose-a-password"
sudo -E .venv/bin/python3 run.py --host 127.0.0.1 --port 5000

# Or pass the secrets inline instead of -E
sudo WIPERX_SECRET_KEY="$WIPERX_SECRET_KEY" WIPERX_ADMIN_PASSWORD="$WIPERX_ADMIN_PASSWORD" \
     .venv/bin/python3 run.py --host 127.0.0.1 --port 5000

# Dev only — throwaway key, no secret needed
sudo .venv/bin/python3 run.py --debug
```

```powershell
# Windows — run an elevated (Administrator) PowerShell, then:
$env:WIPERX_SECRET_KEY = python -c "import secrets;print(secrets.token_hex(32))"
$env:WIPERX_ADMIN_PASSWORD = "choose-a-password"
.venv\Scripts\python.exe run.py --host 127.0.0.1 --port 5000
```

Remote SSH/WinRM wipes started from the GUI do **not** need local root — the
remote host authenticates with its own credentials.

Production (per `run.py`'s app factory):

```bash
sudo -E .venv/bin/gunicorn -w 4 -b 0.0.0.0:5000 "run:create_app_factory()"
```

| URL             | Description                              |
|-----------------|-------------------------------------------|
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

### Per-OS native commands (`--method auto`)

| Strategy            | Command                            | Target           | Notes                                          |
|---------------------|-------------------------------------|------------------|-------------------------------------------------|
| LinuxHDD-Shred      | `shred -v -n 1 -z /dev/sdX`        | SATA HDD         | 1 random pass + zero pass. NIST 800-88 Clear   |
| LinuxSSD-BlkDiscard | `blkdiscard + dd zero`             | SATA SSD         | TRIM + full zero. Use hdparm for full SE       |
| LinuxNVMe-Format    | `nvme format --ses=1`              | NVMe SSD         | Controller-level cryptographic erase           |
| LinuxUSB-DD         | `dd if=/dev/zero of=/dev/sdX bs=1M`| USB drives       | Full sector overwrite                          |
| Windows-DiskPart    | `diskpart clean all`               | Windows all disks| Full zero write; cannot wipe active OS disk    |
| macOS               | `diskutil secureErase` / `dd` to `/dev/rdiskN` | External HDD/SSD/USB | Internal Apple SSD = crypto-erase only |

### Explicit overwrite methods (`--method ...`)

Defined in `core/wipe_passes.py`, used identically across CLI, web, and the erase/wipe-free commands:

| Method | Passes | Description |
|--------|--------|--------------|
| `auto` / `clear` | 2 | NIST SP 800-88 Clear (1 random + 1 zero pass) |
| `zero` | 1 | Single zero-fill pass |
| `random` | 1 | Single random pass |
| `dod` / `dod-3` | 3 | DoD 5220.22-M (E) — 0x00, 0xFF, random |
| `dod-7` | 7 | DoD 5220.22-M (ECE) |
| `gutmann` | 35 | Gutmann — 4 random, 27 patterns, 4 random |
| `nist-purge` | 2 | NIST SP 800-88 Purge — random pass + read-back verify |

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

### Report Signing
- Wipe/erase/recovery reports can be signed with an Ed25519 keypair (`keys/`, gitignored) via `core/report_signer.py`
- `wiperx verify-report <path>` independently verifies the signature, and (if `WIPERX_VERIFY_PUBKEY` is configured) checks the signer against a trust anchor

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

## Testing & CI

```bash
pip install -r requirements-dev.txt   # or: pip install -e ".[dev]"
pytest -q
```

CI (`.github/workflows/ci.yml`) runs on every push and pull request, on Python 3.10, 3.11, and 3.12 (`ubuntu-latest`):

1. Install system deps for forensic recovery: `libmagic1`, `sleuthkit`
2. `pip install -r requirements.txt -r requirements-dev.txt`
3. Lint: `black --check .` and `flake8 .`
4. Test: `pytest -q --cov=core --cov=cli --cov=web --cov-report=term-missing`

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
|------------|--------------|
| HDD shred effectiveness | On some HDDs with automatic remapping (bad sectors), shred may not overwrite all data |
| SSD shred ineffectiveness | Shred is unreliable on SSDs/flash due to wear-levelling and FTL; always use manufacturer's secure erase |
| NVMe requires nvme-cli | `nvme format` requires nvme-cli package on the target system |
| WinRM certificate | Production WinRM requires a valid TLS certificate; self-signed requires `verify_ssl=False` |
| No concurrent wipes | Current implementation doesn't support simultaneous wipe of multiple disks |
| No wipe progress % | dd and shred don't easily report percentage to Python; only raw output is streamed |

---

## Future Improvements

| Feature | Priority | Description |
|---------|----------|--------------|
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

---

## Compliance Reference

- **NIST SP 800-88 Rev.1** — Guidelines for Media Sanitization (Clear, Purge, Destroy)
- **DoD 5220.22-M** — DoD National Industrial Security Program Operating Manual
- **IEEE 2883-2022** — IEEE Standard for Sanitizing Storage
- **ISO 27001 A.8.3.2** — Disposal of media

---

## License

MIT — see [LICENSE](LICENSE).

---

*WiperX — Built for security compliance, enterprise PoC, and academic demonstration.*
