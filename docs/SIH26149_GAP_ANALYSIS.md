# SIH26149 gap analysis

Verified 2026-08-31 against the actual codebase (`git diff --stat`, `git show`, and a full `pytest` run — not filenames or commit messages alone).

## The problem statement

**SIH26149** — *"Design and Development of an Integrated Secure Data Erasure and Advanced File Recovery Tool for Digital Forensics and Data Sanitization"*
Sponsor: National Technical Research Organisation (NTRO) · Theme: Blockchain & Cybersecurity · Prize: ₹1,00,000 · Deadline: 20 September 2026

> Background: organizations, law enforcement, and individuals face two challenges — securely destroying sensitive data, and recovering deleted evidence during forensic investigations. Existing tools generally do one or the other. There's a need for a unified platform integrating secure sanitization with forensic-grade recovery.
>
> Description: three core modules — **(1) Secure Drive Eraser**, **(2) Secure File & Folder Eraser**, **(3) Advanced File Carving and Recovery** — plus verification, audit logging, tamper-resistant reporting, compliance with data-destruction standards, multi-file-system/OS support, and (for recovery) signature/structure-based carving, fragmented reconstruction, automatic classification, confidence scoring, and forensic reporting that preserves evidential integrity.
>
> Expected deliverables: the integrated tool (3 modules), a reporting/audit management system, a GUI dashboard, **validation and testing documentation, user manuals, technical documentation, and performance evaluation reports**.

## Module-by-module status

| Requirement | On `main` before today | Verified state now | Where |
|---|---|---|---|
| **Module 1 — Secure Drive Eraser** | Done, single-pass only | **Extended**: 7 selectable pass tables (Clear/Zero/Random/DoD-3/DoD-7/Gutmann-35/NIST-Purge) + post-wipe entropy verification | `core/wipe_passes.py`, `core/entropy.py` |
| **Module 2 — Secure File & Folder Eraser** | Missing (zero code) | **Built**: batch shred, per-file overwrite + zero-rename-delete, free-space clear + `fstrim`, filesystem-trace scrubbing, post-erase verification via `filefrag`, signed JSON certificate; CLI (`erase-file`, `erase-folder`, `wipe-free`) + web UI (`/eraser/`) | `core/eraser_file/{service,batch,file_shredder,trace_scrubber,verify}.py` |
| **Module 3 — Advanced File Carving & Recovery** | Missing (zero code) | **Built**: read-only acquire + hash → filesystem-aware undelete (Sleuth Kit / `pytsk3`) → signature-based header carving → structure-aware refinement → bifragment-gap carving (handles fragmented JPEGs) → libmagic classification → structural validation → confidence scoring → signed forensic case report; CLI (`recover`) + web UI (`/recovery/`, live SSE log stream, case browser) | `core/recovery/{acquire,fs_recover,signatures,carver_header,carver_structure,carver_fragment,classify,validate,confidence,case_report,service}.py` |
| **Unified reporting / tamper-evident audit** | Drive-erase only, unsigned | **Done across all 3 modules**: Ed25519-signed envelope (`core/report_signer.py`) wraps every report; unified audit view (`/dashboard/audit`) | `core/report_signer.py`, `web/templates/dashboard/audit.html` |
| **GUI dashboard covering all modules** | Wipe workflow only | **Unified** — dashboard, eraser, and recovery UIs share one dashboard/nav | `web/blueprints/{dashboard,eraser,recovery}.py` |
| **Validation & testing documentation** | Thin (218 lines, drive-erase only) | **81 tests, all passing** (verified by running `pytest tests/ -v` on 2026-08-31, see below) across drive-erase, file-erase, carving (contiguous/bifragment/random-gap/garbage/truncated), classification, signing, and web-access-control | `tests/*.py`, 9 new files, 721 lines |
| **User manual / technical docs / performance eval report** | Missing | **Still missing.** These are the one category of explicit problem-statement deliverable with no code equivalent — they're documents, not modules. | — |

### Test run (ground truth, not a claim)

```
$ python -m pytest tests/ -v
...
======================= 81 passed, 84 warnings in 13.67s =======================
```
All 84 warnings are `datetime.utcnow()` deprecation notices (Python 3.13), not failures. Two dependency pins in `requirements.txt` were stale and had to be corrected before this would even install (`pytsk3==20240220` — never a published release; `Pillow==10.3.0` — fails to build against modern setuptools on Python 3.13); fixed and verified in commit `963c05b`.

## What this means

The two modules the problem statement centers on — file/folder erasure and forensic recovery — were **not missing from the project's ability, only from `main`**. They existed, complete and tested, on an unmerged branch (`feat/module2-file-eraser`, 4 commits, all today). That branch has now been merged into `main` (see `docs/ROADMAP.md` Step 3) after the test suite was independently re-run and confirmed green.

## Extras already present that go beyond the bare minimum

These would otherwise have been my top recommendations — turns out they're built:
- **Ed25519 report signing** (tamper-evidence stronger than the HMAC the original README roadmap called for)
- **NIST 800-88 Purge / DoD 5220.22-M / Gutmann 35-pass** wipe modes
- **Bifragment-gap carving** for fragmented files (a materially harder carving problem than plain signature scanning)
- **Confidence-scored recovery** with per-file classification and structural validation, not just raw carved bytes
- **Live SSE log streaming** for long-running recovery jobs in the web UI
- `tools/make_demo_image.sh` + `tools/demo_erase.sh` — ready-made demo scaffolding for a live SIH pitch

## Extras added in the follow-up session (2026-08-31)

hdparm ATA Secure Erase (`core/strategies/LinuxHdparmSecureEraseStrategy`, `--method ata-secure-erase`), a SMART pre-wipe health check (`core/smart_check.py`, advisory-only), and a Docker Compose deployment (`docker-compose.yml` + Nginx) — all three were on the "extras still worth considering" list and are now implemented and tested. See `docs/ROADMAP.md` for verification details.

## Extras still worth considering (not built, lower priority — see ROADMAP.md)

A bootable ISO/PXE story for wiping the running OS disk (the one limitation no software wiper can solve locally), SIEM export, concurrent multi-disk wipes.
