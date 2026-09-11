# WiperX — Failure Modes Catalog

A living record of every known way WiperX can fail, error, or behave unsafely,
plus the state of the fix. Produced from a full read-through of the CLI, core
engine, and Flask web app.

**Status legend**

| Status | Meaning |
|--------|---------|
| `open` | Not yet addressed. |
| `fixed` | Code changed + regression test. |
| `mitigated` | Reduced in likelihood/impact, not fully closed (reason noted). |
| `limitation` | Inherent to software-based sanitisation; documented, won't "fix". |

**Severity**: `crit` (security hole / data-loss / start-up failure) ·
`high` (wrong result, crash on a core page, unattended-run breakage) ·
`med` (degraded behaviour, poor error surface) ·
`low` (cosmetic, rare, well-contained).

Work is tracked in `plans/` and delivered in phases A1–A7 (see the approved plan).

---

## 1. Security (web) — `crit` unless noted

| ID | Symptom | Trigger | Location | Sev | Status |
|----|---------|---------|----------|-----|--------|
| SEC-01 | Report-download serves arbitrary repo files — Ed25519 **signing key**, `.env`, source | `GET /reports/download/cases/../keys/wiperx_sign_key.pem` or `/reports/download/../.env`; VIEWER role is enough | `web/blueprints/reports.py` `_resolve`/`_under` | crit | **fixed** (A1) — reject `..`/absolute/dotfile/`keys`; resolve + `relative_to` against `REPORTS_DIR` \| `CASES_DIR` only; `tests/test_hardening.py::test_report_download_traversal_blocked` |
| SEC-02 | No CSRF protection on any state-changing request — cross-site POST can trigger a real wipe / erase / recovery / machine change | Any authenticated admin/operator browsing a hostile page | `web/app.py` `CSRFProtect(app)` | crit | **fixed** (A1) — `CSRFProtect` + `{{ csrf_token() }}` in 6 forms + `X-CSRFToken` on the 2 fetch POSTs; `test_hardening.py::test_post_without_csrf_token_is_rejected` |
| SEC-03 | Login open-redirect | `GET /auth/login?next=https://evil.com` then authenticate | `web/blueprints/auth.py` `_safe_next` | high | **fixed** (A1) — `next` honoured only if local path; `test_hardening.py::test_login_open_redirect_blocked` |
| SEC-04 | Web eraser can shred **any** path the server can reach (README says run web as root) | `WIPERX_ERASE_ALLOWED_ROOT` unset → `_paths_ok` returns `(True, None)` | `web/blueprints/eraser.py` + `web/blueprints/_fsroot.py` | crit | **fixed** (A1) — fail-closed root (env → home, never `/`); `test_hardening.py::test_eraser_rejects_path_outside_root` |
| SEC-05 | Web recovery can carve **any** readable file, then download the fragments | `WIPERX_RECOVER_ALLOWED_ROOT` unset | `web/blueprints/recovery.py` + `_fsroot.py` | crit | **fixed** (A1) — same fail-closed `allowed_root()` |
| SEC-06 | `wipe_free_mount` is never sandbox-checked even when an allowed-root is configured | Operator submits a free-space mount outside the root | `web/blueprints/eraser.py` `run()` | high | **fixed** (A1) — `wipe_free_mount` folded into the `_paths_ok` check |
| SEC-07 | Werkzeug interactive debugger (RCE) exposed off-localhost | `python run.py --debug --host 0.0.0.0` | `run.py` `__main__` | crit | **fixed** (A1) — `--debug` refused (`exit 2`) unless `--host` is loopback |
| SEC-08 | `/dev/` gate is a bare string check — bypassable | `//dev/sda`, `/DEV/sda`, or a symlink under the allowed root pointing at a device | `web/blueprints/recovery.py:60` | high | open (A4) |
| SEC-09 | `_safe_under` sibling-prefix hole | `filename="../reports2/x"` when a `reports2*` dir exists (string `startswith`, no separator) | `web/blueprints/reports.py` | high | **fixed** (A1) — closed by the SEC-01 `relative_to` rewrite |
| SEC-10 | No login rate-limiting / lockout | Credential brute force | `web/blueprints/auth.py:28-30` (log only) | med | open (A3) |
| SEC-11 | SSH `AutoAddPolicy` (accept any host key) whenever a `known_hosts` file is absent | First connect to any host with no `~/.ssh/known_hosts` / `WIPERX_KNOWN_HOSTS` | `core/executors/ssh_executor.py:126-133` (warning only) | high | open (A4) |
| SEC-12 | bcrypt silently truncates passwords > 72 bytes | Long passphrase | `web/models.py:71-74` | low | open (A3) |
| SEC-13 | Audit log claims "tamper-evident" but is plain mutable JSONL | — | `core/audit_logger.py:12-16` | med | open (A3) — reword or add HMAC chain |
| SEC-14 | Session cookie sent over plain HTTP on `WIPERX_HTTPS` typo (`True `, `1`, `yes`) | Env var not exactly `"true"` | `web/app.py:88` | med | open (A6) |

---

## 2. Crash bugs — unhandled exception → HTTP 500 on a core page (`high`)

| ID | Symptom | Trigger | Location | Status |
|----|---------|---------|----------|--------|
| CR-01 | 500 on dashboard, `/reports/`, `/recovery/cases/` | `cryptography` not importable → `verify_file` → `verify_payload` → `_require_crypto()` raises `RuntimeError` | `core/report_signer.py:320-336` | **fixed** (A2) — `verify_file` catches `RuntimeError`, returns soft dict; `tests/test_hardening.py::test_dashboard_survives_missing_crypto` |
| CR-02 | 500 on `/eraser/run` | non-numeric `passes` form field → `int()` before the try | `web/blueprints/eraser.py` | **fixed** (A2) — `_int()` helper; `test_hardening.py::test_eraser_bad_passes_does_not_500` |
| CR-03 | 500 on `/machines/add` | non-numeric `ssh_port` / `winrm_port` | `web/blueprints/machines.py` | **fixed** (A2) — `_int()` → flash "Invalid port number." |
| CR-04 | 500 on the landing page | report file removed between `glob` and `stat` | `web/blueprints/dashboard.py` | **fixed** (A2) — `_mtime()` swallows `OSError` |
| CR-05 | 500 on `/reports/view/<f>` | path-valid file that is not JSON → `json.load` | `web/blueprints/reports.py` | **fixed** (A2) — try/except → `abort(404)`; `test_hardening.py::test_report_view_non_json_is_404` |
| CR-06 | Any unhandled view error shows the Flask default 500 (or the debugger) | — | `web/app.py` — no `@app.errorhandler` at all | **fixed** (A2) — 404/500/`Exception` handlers render `errors/*.html`, `HTTPException` passes through, debugger kept in `--debug` |
| CR-07 | **CLI + web fail to start** | `logs/` parent missing or unwritable → import-time `LOGS_DIR.mkdir(exist_ok=True)` (no `parents=True`) raises | `core/audit_logger.py:31` | open (A4) |
| CR-08 | 404 handler itself 500s | `base.html` does `'x' in request.endpoint`; `request.endpoint` is `None` on any 404 → `TypeError` (latent; exposed once 404 renders a real template) | `web/templates/base.html` | **fixed** (A2) — `in (request.endpoint or '')` |

---

## 3. Web robustness (`high` / `med`)

| ID | Symptom | Trigger | Location | Sev | Status |
|----|---------|---------|----------|-----|--------|
| WEB-01 | Execute-page spinner hangs forever; SSE stream never ends | Report writer raises (disk full, reportlab) after `execute_wipe` returns — `run_in_thread` has no try/except, so `{"type":"done"}` is never queued and `stream_logs` loops on 30 s heartbeats | `web/blueprints/wipe.py:112-171` | high | **fixed** (A3) — whole `run_in_thread` body wrapped; any exception queues `{"type":"done","success":False,"error":…}`; `tests/test_web_robustness.py::test_thread_death_still_queues_done` |
| WEB-02 | First live stream orphaned, loops emitting heartbeats | Same account starts a second wipe/recovery — queue dict keyed by `current_user.id` is overwritten | `web/blueprints/wipe.py:22,108,188`; `web/blueprints/recovery.py:44,151,194` | med | **mitigated** (A3) — `/wipe/run` + `/recovery/run` return `409` JSON when a queue already exists for the user id (no multiplexing); `tests/test_web_robustness.py::test_second_wipe_run_returns_409`, `::test_recovery_second_run_returns_409` |
| WEB-03 | Wipe **replay** on the same disk | Refresh / re-POST `/wipe/run`, or two tabs — `session["pending_wipe"]` is never cleared | `web/blueprints/wipe.py:54,104` | high | **fixed** (A3) — `session.pop("pending_wipe", None)` at the top of `run_wipe()`; re-POST hits the 400 branch; `tests/test_web_robustness.py::test_pending_wipe_cleared_after_run` |
| WEB-04 | `/wipe/stream/<session_id>` ignores its URL arg (uses `current_user.id`) | — | `web/blueprints/wipe.py:179,188` | low | open (A3) |
| WEB-05 | Role change mid-flight not re-checked inside the worker thread | Role revoked after `/wipe/run` accepted | `web/blueprints/wipe.py:101` vs `:112` | low | open (A3) |
| WEB-06 | Machines added on one worker invisible on others; all state lost on restart; random per-worker demo password + secret key (debug/testing) | Any process restart or multi-worker (`gunicorn -w 4`) deploy | `web/models.py:115-134,159` (in-memory `_USER_STORE` / `_MACHINE_STORE`, evaluated at import) | high | **mitigated** (A3) — opt-in `WIPERX_STATE_DIR`: `_PersistentDict` flushes both stores to `users.json` / `machines.json` on every mutation and reloads at import (seeded trio + hashes persisted so passwords stay stable); default without the env var is unchanged pure-in-memory. Single shared JSON file — not safe for concurrent writers on network storage; a real DB is still the production answer. `tests/test_web_robustness.py::test_state_dir_persists_machines`; README caveat added |
| WEB-07 | `create_app_factory()` (gunicorn) does **not** run the `WIPERX_SECRET_KEY` hard-fail pre-check that `run.py __main__` does | Missing secret key under gunicorn | `web/app.py:71-82` vs `run.py` | med | open (A3) |
| WEB-08 | `machines.test_connection` returns HTTP **200** on hard errors (missing SSH key, DNS failure) | Any connection error | `web/blueprints/machines.py:113-116` | low | open (A3) |
| WEB-09 | `sys.path` grows unbounded (one `insert` per request) | Every `/machines/test/<id>` call | `web/blueprints/machines.py:86` | low | open (A3) |
| WEB-10 | Werkzeug dev server, unbounded threads; each SSE client holds a thread for the whole (possibly multi-hour) wipe | Concurrent live operations | `run.py` `app.run(..., threaded=True)` | med | limitation (document; use gunicorn) |
| WEB-11 | Reports index row order wrong | Mixed timestamp string formats sorted lexically | `web/blueprints/reports.py:145` | low | open (A7) |

---

## 4. Core engine — safety & correctness (`high`)

| ID | Symptom | Trigger | Location | Status |
|----|---------|---------|----------|--------|
| ENG-01 | **System disk not protected** — Safety Check 3 bypassed | `df` / `awk` / `tail` unavailable or fails → `_root_device` returns `None` → every disk gets `is_system=False` | `core/disk_scanner.py:103,223-229` | **fixed** (A4) — `is_system`/`is_mounted` are now `Optional[bool]`; a genuine detection failure sets `None` (never `False`), and `execution_manager.execute_wipe` refuses the wipe outright ("Safety Check 2b") when either is `None`; `tests/test_core.py::TestDiskScannerLinuxFailClosed::test_root_device_detection_failure_is_unknown_not_false`, `::test_unknown_safety_status_is_blocked` |
| ENG-02 | **Mounted disk not flagged** — Safety Check 4 bypassed | `/proc/mounts` unreadable (non-Linux, container) → `_get_mounted_linux` returns `[]` | `core/disk_scanner.py:100,214-221` | **fixed** (A4) — same fail-closed `None` + refuse-on-unknown as ENG-01; `_get_mounted_linux` now returns `None` (not `[]`) on read failure; `tests/test_core.py::TestDiskScannerLinuxFailClosed::test_mount_table_detection_failure_is_unknown_not_false` |
| ENG-03 | System-disk detection false positive/negative | Substring match: `name in root_device` — `sda` matches `/dev/sda1`; one device name a substring of another | `core/disk_scanner.py:183-186` | **fixed** (A4) — new `DiskScanner._base_device_name()` derives the exact whole-disk name from a `/dev/...` path (handles `sdX`, `nvmeXnY`, `mmcblkX` partition suffixes) and both `is_system`/`is_mounted` now compare equality against it, not `in`; `tests/test_core.py::TestDiskScannerLinuxFailClosed::test_exact_device_match_no_false_positive_substring` |
| ENG-04 | Non-system Windows disks **always reported unmounted** | `is_mounted = is_system` hard-coded | `core/disk_scanner.py:282` | open (A4) — query `Get-Partition` |
| ENG-05 | Windows system disk = "disk 0" assumption wrong | OS on a non-zero disk / Storage Spaces | `core/disk_scanner.py:271` | open (A4) |
| ENG-06 | NVMe crypto-erase can hit the **wrong namespace** | `disk.identifier` not `nvme0n1` — command hard-codes `nvme0n1` | `core/strategies/__init__.py:289-292` | **fixed** (A4) — `LinuxNVMeWipeStrategy.execute` now refuses (returns `False`, logs an error) any identifier not matching `nvme\d+n\d+`, instead of silently defaulting to `nvme0n1`; `tests/test_core.py::TestStrategyFactory::test_nvme_strategy_refuses_unexpected_identifier` |
| ENG-07 | A genuinely successful wipe is downgraded to **FAILED** | Scanner couldn't size the disk (`size_bytes==0`) → verifier `sampled==0` → `verified=False` → `execution_manager` downgrades `success` | `core/verifier.py:108-115,196-199`; `core/execution_manager.py:305-313` | **fixed** (A4) — `WipeVerifier._verify_sample` now short-circuits to `verified=None` (inconclusive, `samples=0`) whenever `size_bytes==0`, before any degenerate single-offset sampling happens; `execution_manager` already only downgraded on `verified is False`, so it now correctly leaves an unsized-but-successful wipe alone; `tests/test_fixes_pendrive_analysis.py::test_verifier_unsized_disk_is_inconclusive_not_failed` |
| ENG-08 | macOS multi-pass `dd` runs **unbounded**; `ENOSPC` treated as success | `blockdev --getsize64` (Linux-only) fails → no `count=` | `core/strategies/__init__.py:96-152,529-566` | open (A4) — size via `diskutil info` |
| ENG-09 | Missing backend binary (`shred`/`nvme`/`blkdiscard`/`diskpart`/`diskutil`/`blockdev`/`tr`) surfaces as a generic failed wipe | Binary absent on target | `core/strategies/__init__.py` (many) | open (A4) — `command -v` pre-flight with a clear "install X" message |
| ENG-10 | Windows `diskpart` script likely malformed | PowerShell here-string `\n` not expanded; non-English; quoting | `core/strategies/__init__.py:398-404` | open (A4) |
| ENG-11 | `diskutil secureErase` rejected by most modern SSDs | Modern SSD | `core/strategies/__init__.py:512-527` | limitation (documented; hint text present) |
| ENG-12 | Device path not shell-quoted on most command paths | `disk.identifier` with shell metacharacters (mitigated by exact-match `_find_disk`) | `core/strategies/__init__.py:180,224,330,…` (only `_run_passes*` quote) | open (A4) — quote everywhere |
| ENG-13 | `LocalExecutor` uses `subprocess.run(..., shell=True)` with interpolated device paths | Every local command | `core/executors/__init__.py:98` | open (A4) — move to list-args where feasible |
| ENG-14 | `OSError` / `FileNotFoundError` (fork failure, no shell) propagate raw | Local command | `core/executors/__init__.py:98-117` | open (A4) |
| ENG-15 | Remote wipe stdout capped at 64 KB with no drain → channel can stall until timeout | Wipe with `status=progress` over SSH | `core/executors/ssh_executor.py:53,184-186` | open (A4) — loop-drain + keepalive |
| ENG-16 | Multi-hour remote wipe dropped by NAT/idle timeout, reported FAILED though still running on target | Long SSH/WinRM wipe, no keepalive | `core/executors/ssh_executor.py:177-202`; `core/executors/winrm_executor.py:127-133` (`timeout` param ignored) | open (A4) |
| ENG-17 | Remote **Windows privilege check is a no-op** — non-admin remote user not blocked | Remote WinRM target | `core/execution_manager.py:450-454` | open (A4) |
| ENG-18 | `scan_disks` remote errors (auth, missing key, unsupported OS) propagate **unwrapped** to callers | Remote scan failure | `core/execution_manager.py:133,389,401` | open (A4/A5) |
| ENG-19 | Unknown `--method` silently falls back to `auto` (twice) | Bad method reaches the manager | `core/execution_manager.py:259-261`; `core/wipe_passes.py:125,132` | open (A5) — warn |
| ENG-20 | `finally: executor.close()` can raise and mask the original exception | `close()` throws | `core/execution_manager.py:358-360` | open (A4) |
| ENG-21 | New signing identity generated silently on a fresh checkout / wiped `keys/` → old certificates stop chaining to the anchor | `keys/wiperx_sign_key.pem` absent | `core/report_signer.py:124-150` (warning only) | open (A7) — louder / require opt-in |
| ENG-22 | Corrupt / encrypted / wrong-format signing key raises inside `load_private_key` (not caught) | Bad `WIPERX_SIGN_KEY` PEM | `core/report_signer.py:117-119` | open (A4) |
| ENG-23 | `verify_file` `RuntimeError` when crypto missing (web) | see CR-01 | `core/report_signer.py:320-326` | open (A2) |
| ENG-24 | Post-wipe verification exception is swallowed (non-fatal, `verified=None`) | `WipeVerifier` throws | `core/execution_manager.py:295-299` | mitigated (by design; note in report) |
| ENG-25 | `expected="random"` final pass ⇒ wipe is never verifiable (`verified=None`) | `--method random` / any random-terminated method | `core/verifier.py:185-188` | limitation (report-only by design) |

---

## 5. Module 2 — file/folder eraser (`med` / `high`)

| ID | Symptom | Trigger | Location | Status |
|----|---------|---------|----------|--------|
| ER-01 | Files under a permission-denied subdirectory are **never shredded and never reported** | `os.walk` has no `onerror` | `core/eraser_file/batch.py:63` | open (A4) |
| ER-02 | No mount-boundary / system-path guard — CLI has **no sandbox at all** | `wiperx erase-folder /` or a mount point | `core/eraser_file/batch.py:57-75`; `cli/wiperx_cli.py` | open (A5) — add a refuse-list + `--i-know` |
| ER-03 | Free-space fill runs the filesystem to near-full (32 MiB reserve) → other processes get `ENOSPC` during the run | Always, during `wipe-free` / `--wipe-free` | `core/eraser_file/trace_scrubber.py:102,122-146` | limitation (inherent) — raise the reserve, document |
| ER-04 | `.wiperx_fill_*` temp files **leak, filesystem stays full** | Process SIGKILL/OOM before the `finally` unlink | `core/eraser_file/trace_scrubber.py:147-152` | open (A4) — startup sweep of stale fill files |
| ER-05 | File left **partially overwritten** on `ENOSPC` during overwrite (CoW FS: btrfs/ZFS/APFS) | In-place overwrite consumes space | `core/eraser_file/file_shredder.py:52-72,132-141` | limitation — document; `ok=False` is returned |
| ER-06 | `MemoryError` from `os.urandom` propagates (not captured in `ShredResult`) | Huge `chunk_size` | `core/eraser_file/file_shredder.py:135` | open (A4) |
| ER-07 | `_prune_dirs` `os.rmdir` failures swallowed → leftover directories, no error surfaced | Non-empty / no-permission dir | `core/eraser_file/batch.py:84-96` | low — open (A7) |
| ER-08 | Raw slack-zeroing can write zeros at a **wrong raw device offset** → corruption | `WIPERX_ALLOW_RAW_SLACK=1` + root + Linux + `filefrag` misparse (version/locale) | `core/eraser_file/trace_scrubber.py:238-271,334-358` | open (A4) — guard offsets / keep behind flag + warn |
| ER-09 | `cert_path.write_text` failure (disk full, `reports/` permission) not caught → propagates to CLI/web broad except | Signing-key missing → unsigned fallback write fails | `core/eraser_file/service.py:258,337` | open (A4) |
| ER-10 | Erase verification silently unavailable off Linux / non-root | `_verify_after_erase` needs `filefrag` | `core/eraser_file/service.py:74-131` | limitation — document |
| ER-11 | `erase-file`/`erase-folder` with `--passes 0` → `ValueError` re-raised out of the worker → CLI "FATAL" / web 500 | `--passes 0` | `core/eraser_file/file_shredder.py:101-106`; `core/eraser_file/batch.py:151-153` | open (A2 for web via `_int`; A5 for CLI) |

---

## 6. Module 3 — forensic recovery (`med`)

| ID | Symptom | Trigger | Location | Status |
|----|---------|---------|----------|--------|
| RC-01 | Recovery may proceed on a **live read-write disk** on non-Linux | `_rw_mounted` parsing of `mount` output is fragile; `/proc/mounts` unreadable → returns `False` | `core/recovery/acquire.py:45-69` | open (A4) — fail closed |
| RC-02 | `PermissionError` opening a device (no sudo) → CLI "FATAL" / web "done fail" with a raw message | `os.open(path, O_RDONLY)` needs root | `core/recovery/acquire.py:200` | open (A5) — clear "run as root" message |
| RC-03 | Output dir not writable → `PermissionError`, no pre-check | `Case.__init__` `recovered_dir.mkdir` | `core/recovery/acquire.py:231` | open (A5) |
| RC-04 | `.E01` / EWF evidence image read as raw bytes → **silent garbage carves** | `libewf-python` not installed (commented out) | `core/recovery/acquire.py` (no format detection) | open (A7) — detect + refuse with a hint |
| RC-05 | Whole recovery aborts | A carver returns a path not under `case.dir` → `Path.relative_to` `ValueError` uncaught | `core/recovery/service.py:156` | open (A4) |
| RC-06 | Recovery aborts on a failing device (bad sectors) | Background SHA-256 thread hits `OSError`, re-raised via `hash_future.result()` | `core/recovery/acquire.py:110-127`; `core/recovery/service.py:158` | mitigated (comment acknowledges) — open (A4) |
| RC-07 | Deleted files > 512 MB silently truncated | `read_random(0, min(size, 512MB))` | `core/recovery/fs_recover.py:118` | limitation — flag is set (`data_readable=False`) |
| RC-08 | CLI-backend `fpath.write_bytes` on full/unwritable output propagates unwrapped | sleuthkit CLI path, disk full | `core/recovery/fs_recover.py:195` | open (A4) |
| RC-09 | Degraded backends (no sleuthkit / libmagic / Pillow / pypdf / mutagen) → user only learns via notes/counts in the final report | Optional deps absent (common on macOS/Windows) | `core/recovery/*` | open (A5) — upfront capability check + non-zero exit |
| RC-10 | `PRAGMA integrity_check` on a multi-GB carved SQLite blob can hang the enrich loop (no timeout) | Large SQLite carve | `core/recovery/validate.py:105-116` | open (A4) |
| RC-11 | `carve-only` fallback rescans the **entire source** even when the fs pass mapped live data | Allocated-range extraction is a stub returning `[]` | `core/recovery/fs_recover.py:16-18,50-51` | open (performance follow-up, already noted in code) |
| RC-12 | Global `ImageFile.LOAD_TRUNCATED_IMAGES` mutation not thread-safe | Image validation | `core/recovery/validate.py:66-75` | mitigated (enrich loop is serial today) |

---

## 7. CLI (`high` / `med`)

| ID | Symptom | Trigger | Location | Status |
|----|---------|---------|----------|--------|
| CLI-01 | `wipe` **cannot run unattended** — 4 interactive prompts, no `--yes`/`--force`; appears to hang on stdin | cron / CI / pipe / subprocess with no TTY | `cli/wiperx_cli.py:174,180,188,194` | open (A5) |
| CLI-02 | Raw `KeyError` traceback | `getpass.getuser()` (prompt default) evaluated before the try, no resolvable username | `cli/wiperx_cli.py:194` | open (A5) |
| CLI-03 | `recover` **always exits 0** — 0 files recovered / partial failure / degraded backends never signalled | Any recovery outcome short of a FATAL exception | `cli/wiperx_cli.py:462` | open (A5) |
| CLI-04 | Successful wipe → CLI exits 1 "FATAL" with **no report saved** | `open()` write error in `generate_json_report` / PDF after the wipe | `cli/wiperx_cli.py:242-260` | open (A4/A5) |
| CLI-05 | "SECRET_KEY not set" with no hint | `.env` present but `python-dotenv` not installed → silent `except Exception: pass` | `cli/wiperx_cli.py:34-39`; also `run.py`, `web/app.py:33-38` | open (A5/A6) |
| CLI-06 | `.env` silently not found when run from another directory | `load_dotenv()` searches from CWD | `cli/wiperx_cli.py:34-39` | open (A5) — search from repo root |
| CLI-07 | `wipe-free` shows a raw traceback if the service ever raises (it's designed to return a soft dict) | Unexpected exception in `wipe_free_space_only` | `cli/wiperx_cli.py:403` | open (A5) |
| CLI-08 | `--wipe-free <mount>` value not validated (plain `str` option, unlike the positional `click.Path`) | Bad mount string | `cli/wiperx_cli.py:342-343` | open (A5) |
| CLI-09 | Uncaught exception anywhere outside a per-command `try` → full traceback to the user | Import/helper error | CLI-wide (no global handler) | open (A5) |
| CLI-10 | Console-script entrypoint doesn't configure logging (only `__main__` does) | `wiperx ...` after `pip install -e .` | `cli/wiperx_cli.py:30,626` | low — open (A5) |

---

## 8. Config / dependencies (`high` / `med`)

| ID | Symptom | Trigger | Location | Status |
|----|---------|---------|----------|--------|
| CFG-01 | `pip install -r requirements.txt` **fails on any machine without sleuthkit dev headers** | `pytsk3>=20250312` listed unconditionally; builds from sdist against system `libtsk` | `requirements.txt:36` | open (A6) — move to `requirements-forensics.txt` / rely on `.[forensics]` |
| CFG-02 | `requirements.txt` ⇄ `setup.py` extras drift; `python-magic` / `Pillow` / `pypdf` / `mutagen` / `requests-credssp` also unconditional | Same as CFG-01 | `requirements.txt:37-41`, `16` | open (A6) |
| CFG-03 | Non-reproducible installs; a future Flask-Login / Flask-WTF / bcrypt / cryptography release can break at install or runtime | `>=` lower bounds only, no lock file / hashes | `requirements.txt` | open (A6) — optional `pip-compile` lock |
| CFG-04 | `WIPERX_HTTPS` only matches literal `"true"` → cookie non-Secure on `1`/`yes`/`on` | Env var value | `web/app.py:88` | open (A6) |
| CFG-05 | CI matrix is 3.10–3.12 though `Pillow>=11` was pinned for 3.13; `setup.py` says `>=3.10` | — | `.github/workflows/ci.yml` | open (A6) — add 3.13 |
| CFG-06 | `WIPERX_ERASE_ALLOWED_ROOT` / `WIPERX_RECOVER_ALLOWED_ROOT` behave asymmetrically: **unset ⇒ no sandbox**, but a non-existent dir ⇒ every path rejected | Env misconfiguration | `web/blueprints/_fsroot.py` | **fixed** (A1) — unset ⇒ fail closed to `Path.home()`, refuse a `/` root outright |
| CFG-08 | **CI has never passed** — `black --check .` wants to reformat ~51 files repo-wide (target-version / never-formatted); every CI run on `main` and branches is red, so lint+tests never actually gate | Any push | `.github/workflows/ci.yml` Lint step; `pyproject.toml [tool.black]` | open (A6) — one-time `black .` sweep + `flake8-pyproject` (flake8 doesn't read `pyproject.toml` natively, so the `[tool.flake8]` block is currently ignored) |
| CFG-07 | Ephemeral random `SECRET_KEY` under `--debug`/TESTING diverges per gunicorn worker → login breaks across workers | Multi-worker debug run | `web/app.py:72-77` | open (A3) — document / require explicit key |

---

## 9. Design limitations — documented, not "bugs"

These are inherent to software-based sanitisation and already noted in `README.md`
/ `WIPERX_ANALYSIS_REPORT.md`. Listed here for completeness.

| ID | Limitation |
|----|-----------|
| LIM-01 | Cannot wipe the running-OS disk (mounted root / Windows Disk 0). Use PXE boot / bootable ISO / WinPE. |
| LIM-02 | `shred` is unreliable on SSDs/flash (wear-levelling, FTL) and on HDDs with automatic bad-sector remapping. Use the manufacturer secure-erase. |
| LIM-03 | Apple-silicon internal SSD: sector overwrite is refused; only *Erase All Content and Settings* (hardware crypto-erase) applies. |
| LIM-04 | `nvme format` needs `nvme-cli` on the target. |
| LIM-05 | Production WinRM needs a valid TLS certificate; self-signed requires `verify_ssl=False` (lab only). |
| LIM-06 | No concurrent wipes; no percentage progress from `dd`/`shred` (only streamed raw output). |
| LIM-07 | File shredding cannot reach filesystem journals, snapshots, or SSD over-provisioned area. |

---

## 10. Test coverage of failure modes

**Already covered** — `tests/test_core.py` (disk-not-found, name-mismatch,
system/mounted safety matrix, failed-command `RuntimeError`),
`tests/test_eraser_file.py` (non-recursive dir skipped, symlink skip,
`PermissionError` → `ShredResult` not exception),
`tests/test_recovery.py` (`open_source` rejects missing source, optional-lib
`importorskip`), `tests/test_wipe_passes.py` (unknown method / invalid
`PassSpec`), `tests/test_macos.py` (root-device resolution failure),
`tests/test_fixes_pendrive_analysis.py` (scanner misclassification regressions),
`tests/test_web.py` (RBAC 403 / 400 / 404 smoke).

**Covered in A3** (`tests/test_web_robustness.py`): `wipe.py` thread dying with
no `done` · SSE queue collision (409) · `pending_wipe` replay ·
`WIPERX_STATE_DIR` store persistence.

**Covered in Part C** (`tests/test_browse.py`): `/browse/list` listing shape +
dirs-first ordering · `..` rejection · sandbox-root confinement (403) ·
wipe-permission gate (viewer → 403).

**Pre-existing flaky set — order/timing dependent, NOT introduced by A3, Part C,
or Part B** (reproduced on a clean tree, each passes in isolation): a rotating
subset of `tests/test_recovery.py` carver tests fails on a full `pytest` run
but not consistently the same ones - observed so far:
`test_recovery_case_view_via_web` (carve yields 0 files),
`test_random_filler_yields_no_false_positives`, and
`test_genuine_footerless_file_still_carved`. Never more than one per run,
never reproduces standalone. Root cause not yet isolated — likely global
carver / `PIL` state left by an earlier test (cf. RC-12). Triage in A4.

**Known gap — no coverage yet** (added in A7):
missing-`WIPERX_SECRET_KEY` hard-fail ·
`reports.py` `cases/..` traversal to `keys/` · login open-redirect ·
`int()`/`stat()` → 500 in `eraser`/`machines`/`dashboard` ·
unsized-disk → verification-FAIL downgrade · `audit_logger` import-time `mkdir`
failure.

**Latent test mismatch — reconciled (A4)**: that note referred to
`get_strategy`'s existing `ValueError` for an unsupported OS
(`tests/test_core.py::test_unsupported_os_raises`); `core/disk_scanner.py`'s
`DiskScanner.scan()` raised the inconsistent `RuntimeError` for the same
condition with no test covering it. `scan()` now raises `ValueError` too,
covered by `tests/test_core.py::TestDiskScannerLinuxFailClosed::
test_unsupported_os_scan_raises_value_error`.

---

*Generated for the hardening effort. Update the Status column as phases land;
keep the "test coverage" section in sync with `tests/`.*
