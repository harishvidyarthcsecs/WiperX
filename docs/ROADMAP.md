# WiperX roadmap

Status as of 2026-08-31. See `docs/SIH26149_GAP_ANALYSIS.md` for the problem-statement mapping this roadmap is closing.

## Done today (verified, not assumed)

| Step | What happened | Verification |
|---|---|---|
| 1. Run the real test suite | Checked out `feat/module2-file-eraser`, built a venv, installed `requirements.txt` | Two stale pins blocked install and were fixed: `pytsk3==20240220` (never published; repinned to `20260715`) and `Pillow==10.3.0` (fails to build on Python 3.13; repinned to `11.3.0`). Fix committed as `963c05b`. |
| — | Ran `pytest tests/ -v` | **81 passed, 0 failed**, 84 cosmetic `datetime.utcnow()` deprecation warnings only |
| 2. Claude-vs-Codex note in `wipe_passes.py`/`entropy.py` | Confirmed with project owner: no Codex variant exists elsewhere; the comment is stale | Current implementation is final |
| 3. Merge to `main` | `feat/module2-file-eraser` → `main`, fast-forward, confirmed with project owner in advance | `git log --oneline` on `main` now includes all 4 feature commits + the dependency fix |
| 4. Update `README.md` | Project Structure, CLI Usage, Web App Usage, Wipe Strategies, and Future Improvements sections extended to cover Module 2 & 3 | Diff in this same session |
| — | This gap-analysis + roadmap doc | This file and `docs/SIH26149_GAP_ANALYSIS.md` |

**Not yet done:** the merge is local only — `main` has not been pushed to `origin`. Push explicitly when ready (`git push origin main`); holding off since pushing is outward-facing and wasn't separately confirmed.

## Immediate next steps (real work, not code)

- **Step 5 — Formal deliverables.** The problem statement explicitly lists a user manual, technical/architecture documentation, and a performance evaluation report as deliverables. None exist yet; the README is developer-facing, not a user manual. Concretely:
  - *User manual*: install → scan → wipe → erase-file/folder → recover, screenshot-driven, for an operator with no dev background.
  - *Technical documentation*: architecture (the diagram in README is a start), data flow through each module's `service.py`, the report-signing scheme, threat model / what each safety layer defends against.
  - *Performance evaluation report*: needs real numbers — carving accuracy/false-positive rate and speed on a benchmark image set, wipe throughput per strategy, recovery time vs. source size. `tools/make_demo_image.sh` is the seed for generating that benchmark data.
- **Step 7 — Demo verification.** `tools/make_demo_image.sh` and `tools/demo_erase.sh` exist and were read end-to-end this session — they're self-contained (build a loopback ext4 image under `/tmp`, never touch a real disk) and safe to run. They need `sudo` (root for `losetup`/`mkfs.ext4`/`mount`), which wasn't available non-interactively in this session. **Run manually:**
  ```
  sudo tools/make_demo_image.sh
  sudo tools/demo_erase.sh <LOOP> <MNT> <IMG>   # values printed by the line above
  ```
  This is also the natural basis for the SIH live-demo script — it already narrates itself ("plain rm leaves data recoverable, wiperx erase-file + wipe-free doesn't").
- A parallel recovery-side demo (recover a deliberately-deleted file from the same image, show classification/confidence/signed case report) doesn't exist as a script yet — worth adding alongside `demo_erase.sh` for a complete "erase vs. recover" pitch.

## Done in the follow-up session (2026-08-31, later same day)

All of Part A above (docs + recovery demo script) landed, plus 3 backlog items, each verified for real, not just authored:

| Item | Verification |
|---|---|
| `docs/PERFORMANCE_EVALUATION.md`, `docs/TECHNICAL_DOCUMENTATION.md`, `docs/USER_MANUAL.md` | Manual has 13 real screenshots captured via Playwright against a live `python run.py` instance, including an actual erase run and an actual ~103s recovery run through the browser UI |
| `tools/demo_recover.sh` | Actually executed end-to-end (not just read-verified like `demo_erase.sh`) — needs no root at all; recovered a deliberately-deleted file, confirmed byte-exact content, verified the signed case report |
| **Bug found + fixed**: `web/templates/recovery/case.html` crashed with a 500 on any case containing a filesystem-undelete record (the common case — not just carved files), because it assumed every record has an `offset` field. Fixed, and covered by a new regression test (`tests/test_web.py::test_recovery_case_view_renders_fs_recovered_record`) that specifically exercises an `fs`-method record | 82/82 tests passing after the fix; found via the screenshot-capture work itself, not a separate audit |
| **hdparm ATA Secure Erase** | `core/strategies/LinuxHdparmSecureEraseStrategy` — frozen-drive detection, unsupported-feature detection, clean failure handling; 9 new tests, all passing |
| **Docker Compose deployment** | `Dockerfile` + `docker-compose.yml` + `deploy/nginx.conf` — actually built (`docker build`) and run (`docker run`), health-checked, confirmed hdparm/mkfs.ext4/debugfs/nvme/fls all present in the image. One real bug found and fixed along the way: `psutil` needs `gcc`/`python3-dev` to compile on this base image, not present by default. `docker-compose.yml` itself validated for YAML correctness (no `docker compose` plugin installed in this environment to run `config` directly) |
| **SMART health pre-check** | `core/smart_check.py` — advisory-only `smartctl -H -A` wrapper, wired into `execute_wipe()` as a non-blocking pre-check and exposed standalone as `wiperx smart <disk>`; 5 new tests, all passing |

Also fixed along the way: two stale `requirements.txt` pins that blocked `pip install` in a fresh venv have been carried forward from the prior session's fix (`pytsk3`, `Pillow`), and `gunicorn` was added as the production WSGI dependency the README's Quick Setup already referenced but `requirements.txt` never listed.

## Backlog (lower priority, not started)

- **Database backend** — replace in-memory stores with PostgreSQL (High)
- **LDAP/AD auth** — enterprise SSO (High)
- **SIEM integration** — forward audit logs to Splunk/Elastic (High)
- **Disk progress bar**, **concurrent wipe**, **S3 report upload**, **wipe scheduling**, **REST API** (Medium)
- **Bootable ISO / PXE** for wiping the running OS disk — the one limitation no software wiper can solve locally; README already documents the DRBL/FOG/WinPE approach but nothing is built
- A `docker compose config` validation pass once the compose plugin is available in a dev environment (only Dockerfile-level build/run was verified this session)

## Timeline note

SIH26149 deadline: **20 September 2026**. As of this session: all three required modules are implemented, tested (96/96), documented (user manual with real screenshots, technical docs, performance evaluation with real benchmark numbers), containerized, and have a working demo script for both the erase and recovery sides. Remaining realistic pre-submission work is `main` → `origin` push (currently local-only, pending explicit go-ahead) and, time permitting, the backlog above.
