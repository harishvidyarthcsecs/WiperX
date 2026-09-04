# WiperX — Analysis, Fixes, and Destructive Pendrive Retest

Date: 2026-09-04 · Branch: `fix/pendrive-analysis-fixes` (off `feat/module2-file-eraser`)
Test host: macOS 15.7.1 arm64 · `.venv311` (CPython 3.11.16) · pendrive `/dev/disk8` (8.05 GB, FAT32)

---

## 1. Executive summary

| Area | Verdict |
|---|---|
| **Module 1 — device wipe** | **Works.** Full `wiperx wipe disk8` zeroed the whole 8 GB stick; read-back verifier confirmed 256/256 samples zeroed. Partition-only wipe (`wipe disk8s1`) added. |
| **Module 2 — file / folder erase** | **Works.** A 2-pass `erase-file` destroyed its marker on the raw device (scanned all 8 GB, gone); a plain `rm` left the same-size marker fully present. `erase-folder` removed a nested tree. All certs Ed25519-signed and verify. |
| **Module 3 — recovery / carving** | **Works after a fix, but slow and low-precision.** It returned *nothing* on macOS until a size bug was fixed (see #18); after the fix it carved a deleted JPEG back **byte-exact** with `confidence=high`. It is impractically slow on real multi-GB media (#19) and floods results with 48 MB junk files from footerless magic hits (#20). |
| **Signing / verification** | **Works.** Valid → `VALID` exit 0; 1-byte tamper → `INVALID` exit 1; foreign signing key → `VALID (UNTRUSTED SIGNER)` exit **1** (was 0 before the fix). |
| **Unit tests** | **110 passed** (`pytest`, `.venv311`). 1 pre-existing flaky test excluded (bifragment carver, see #16b). |

**User's hypothesis — confirmed:** after a proper wipe, recovery software finds
nothing. `recover` on the wiped device returned **0 files**; the wiped medium
contained 0 non-zero bytes and no file signatures anywhere.

---

## 2. Live pendrive retest results

| Test | What was done | Result |
|---|---|---|
| **D1 — recovery (positive)** | Wrote a marked JPEG to the stick, `rm`'d it, imaged a 400 MB slice, ran `recover --carve-only`. | **PASS** — deleted `probe.jpg` recovered **byte-exact** (2557 B, valid SOI+EOI, marker intact, `validation=intact`, `confidence=high`). 9 false-positive 48 MB `.gz`/`.mp3` carves, all correctly scored `confidence=low`. |
| **D2 — file erase** | `wiperx erase-file A_erase.bin --passes 2`, then scanned the entire raw `/dev/disk8` for its 32-byte token. | **PASS** — token **GONE** (8053 MB scanned, not found). |
| **D2 — rm control** | `rm C_rmonly.bin`, scanned raw device for its token. | Token **FOUND at offset 20,557,824** after 34 MB — `rm` leaves the data. |
| **D2 — folder erase** | `wiperx erase-folder tree/` (nested d1/d2). | **PASS** — tree fully removed, cert signed. |
| **D3 — full device wipe** | `wiperx wipe disk8 --method zero --force-unmount`. | **PASS** — safety checks 1-4 passed, `diskutil unmountDisk force` then `dd if=/dev/zero of=/dev/rdisk8 bs=1m count=7680`, exit 0, signed cert. |
| **D4 — post-wipe verify** | Entropy read-back inside D3. | **PASS** — 256/256 samples `zeroed`, `nonzero=0`, `read_errors=0`, `read_error_ratio=0.0`, entropy 0.00, coverage 0.013%. |
| **D5 — recovery (negative)** | Imaged a 400 MB slice of the wiped stick, checked bytes + ran `recover`. | **PASS** — 0 non-zero bytes, no PNG/JPEG/PDF/ZIP magic; `recover` → **0 files**. Recovery defeated. |
| **D6 — signatures** | verify-report on all run certs + tamper + foreign key. | **PASS** — valid=exit 0, tamper=exit 1, untrusted signer=exit 1 (0 with `--allow-untrusted`). |

Pendrive was reformatted MS-DOS FAT32 (`DISK_IMG`, mounted) at the end. A copy of
the original folders (`Boot_`, `pendrive_Maths`, `pendrive_OS`) is at
`~/Downloads/pendrive_backup_20260904_152025/` (126 files, 564 K).

---

## 3. The 17 findings from the analysis — all fixed

| # | Sev | File | Fix applied |
|---|---|---|---|
| 1 | High | `core/verifier.py` | `_verify_sample` no longer fails on a single transient read error. New rule: any live-looking sample → FAIL; ≤10% unreadable → PASS; >10% unreadable → INCONCLUSIVE. Added `READ_ERROR_TOLERANCE`, `read_error_ratio`. |
| 2 | High | `core/eraser_file/file_shredder.py` | `_overwrite` now takes a `source` callable; random passes call `os.urandom` **per chunk** — a >1 MiB file no longer gets one repeating 1 MiB block. |
| 3 | High | `core/disk_scanner.py`, `core/strategies/__init__.py`, `cli/wiperx_cli.py` | `_scan_macos` emits a `DiskInfo` per partition (`is_partition`, `parent_identifier`, own `size_bytes`, inherited `is_system`). `MacOSWipeStrategy` unmounts the slice (`diskutil unmount force`) not the whole disk when targeting a partition. `wiperx wipe disk8s1` now works. |
| 4 | Med | `core/verifier.py` | Fast path: for a local wipe, `open(dev,'rb')` + `seek/read` once instead of 256 `dd \| od` subprocesses (512-aligned). `dd\|od` kept for SSH/WinRM. |
| 5 | Med | 9 files, 15 sites | New `core/timeutils.py` (`utc_now/utc_iso/utc_stamp`); every `datetime.utcnow()` replaced with tz-aware calls, `…Z` output format preserved. |
| 6 | Med | `core/execution_manager.py`, `cli/wiperx_cli.py` | A wipe whose read-back verification returns `verified is False` now sets `WipeResult.success=False` + `error=`; CLI prints the verdict and exits non-zero. `verified is None` (inconclusive) stays non-fatal. |
| 7 | Med | `core/eraser_file/batch.py`, `service.py` | Shredding a file now also shreds its macOS `._<name>` AppleDouble sidecar. `COMPLIANCE_NOTE` documents that `.Spotlight-V100` / `.fseventsd` / `.DS_Store` / `.Trashes` filename traces need a full-device wipe. |
| 8 | Med | `requirements.txt`, `requirements-dev.txt` (new), `setup.py` | `==` pins → `>=`; impossible `pytsk3==20260715` → `>=20250312`; dev tools split into `requirements-dev.txt`; `setup.py` `install_requires` completed + `extras_require` (`forensics`, `remote-windows`, `dev`). |
| 9 | Med | `pyproject.toml` (new), `.github/workflows/ci.yml` (new) | `[tool.pytest.ini_options]` + coverage + black + flake8 config; CI matrix 3.10/3.11/3.12 running pytest+cov, black --check, flake8. |
| 10 | Low | `core/execution_manager.py` | Local Windows path now checks `ctypes.windll.shell32.IsUserAnAdmin()` and refuses if not elevated. |
| 11 | Low | `tests/test_fixes_pendrive_analysis.py` (new) | 9 tests: verifier tolerance (3), fresh-random shredder, partition target (2), swallowed-verify downgrade, verify-report trust exit, import purity. |
| 12 | Low | `tools/make_demo_image_macos.sh`, `tools/demo_erase_macos.sh` (new) | macOS "Demo A" using `hdiutil attach -nomount` / `diskutil eraseDisk` / `sync; purge`. |
| 13 | Low | `README.md` | macOS row in the platform table + macOS quick-setup block; partition-wipe example. |
| 14 | Low | `run.py` | `create_app_factory()` moved above `__main__`; `load_dotenv()` added; gunicorn hint fixed. |
| 15 | Low | `web/app.py`, `web/models.py` | `WIPERX_SECRET_KEY` now **required** for a non-debug run (was a constant fallback). Demo passwords come from `WIPERX_{ADMIN,OPERATOR,VIEWER}_PASSWORD`; random + logged if unset. `.env.example` added. |
| 16 | Low | `cli/wiperx_cli.py`, `web/app.py`, `run.py` | Guarded `load_dotenv()` at each entry point; `.env.example` documents every `WIPERX_*` var; `.gitignore` += `.env`. |
| 17 | Med | `cli/wiperx_cli.py`, `core/report_signer.py` | `verify_payload` exposes `anchor_configured`; `verify-report` exits non-zero for an untrusted signer when an anchor is set, unless `--allow-untrusted`. |

*(16b — pre-existing, not fixed: `tests/test_carver_fragment.py::test_bifragment_recovered_byte_exact`
fails a random ~1-in-6 gap size each run — the Codex-owned bifragment carver is
not deterministic / not byte-exact. Documented, out of scope for this pass.)*

---

## 4. New findings from the destructive retest

| # | Sev | Status | Detail |
|---|---|---|---|
| **18** | **High** | **FIXED this session** | `core/recovery/acquire.py` `open_source` used `os.lseek(fd, 0, SEEK_END)` to size a device. On a macOS **block** device that returns **0**, so `Source.read()` returned `b""` for everything and recovery silently found nothing. Added `_device_size_fallback` (macOS `DKIOCGETBLOCKCOUNT`/`DKIOCGETBLOCKSIZE` ioctls, then `diskutil info -plist`; Linux `BLKGETSIZE64`) and a hard error if size is still 0. Recovery then works (D1). |
| **19** | **High** | Open | `core/recovery/carver_header.carve` scans the source byte-by-byte in pure Python (`iter_header_hits` → `match_at` at every offset). ~17 min per 400 MB; the full-source SHA-256 pass adds ~10 min for 8 GB. Unusable on real multi-GB media. Needs `mmap` + `bytes.find`/compiled-regex magic scan, and the whole-source hash should be optional / streamed alongside carving. |
| **20** | **Med** | Open | A footerless magic hit (`gzip \x1f\x8b`, `mp3`, …) carves the full `sig.max_bytes` (48 MB) → results flood with huge junk files. `by_confidence` correctly bands these `low`, but they still cost time and disk. Tighten the header guard / cap footerless carves, or skip when the tail is high-entropy random. |
| 21 | Low | Open | On this FAT32 stick the macOS `fskit` driver does **not** zero deallocated clusters on unmount+sync — a deleted file's bytes (incl. a valid JPEG SOI) remained on the raw device. Good for the "recovery works" demo; worth noting in the compliance text that free-space is not self-clearing. |

---

## 5. Files changed (branch `fix/pendrive-analysis-fixes`, no commits)

New: `core/timeutils.py`, `pyproject.toml`, `requirements-dev.txt`, `.env.example`,
`.github/workflows/ci.yml`, `tools/make_demo_image_macos.sh`,
`tools/demo_erase_macos.sh`, `tests/test_fixes_pendrive_analysis.py`.

Modified: `core/verifier.py`, `core/eraser_file/{file_shredder,batch,service}.py`,
`core/execution_manager.py`, `core/disk_scanner.py`, `core/strategies/__init__.py`,
`cli/wiperx_cli.py`, `core/report_{signer,generator,paths}.py`, `core/audit_logger.py`,
`core/recovery/{acquire,case_report}.py`, `web/{app,models}.py`,
`web/blueprints/recovery.py`, `tests/{conftest,test_macos}.py`,
`requirements.txt`, `setup.py`, `run.py`, `README.md`, `.gitignore`.

Behaviour changes to be aware of before merging:
- `python run.py` now exits 1 without `WIPERX_SECRET_KEY` (use `--debug` for a throwaway key).
- Web login passwords now come from `WIPERX_{ADMIN,OPERATOR,VIEWER}_PASSWORD` env vars.
- `wiperx wipe` exit code now reflects post-wipe verification.
- `wiperx verify-report` exit code now reflects trust, not just signature validity.

---

## 6. Still open

- **#19 / #20** — recovery performance + false-positive flood (design work, not a quick patch).
- **#16b** — bifragment carver non-determinism.
- Linux partition-target scan is best-effort only (macOS path is complete).
- `libmagic` not installed on the test host — carving used the built-in
  signature-sniffing fallback (works; classification `source` reads `signature`
  not `libmagic`).
- Whole-device Module 1 wipe leaves the medium with no partition table; the
  operator must reformat (done here automatically for the pendrive).
