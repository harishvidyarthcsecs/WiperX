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

## Backlog (lower priority, not started)

From the original README roadmap, still open after Module 2/3 landed:

- **hdparm ATA Secure Erase** — true hardware-level SSD erase (High)
- **Database backend** — replace in-memory stores with PostgreSQL (High)
- **LDAP/AD auth** — enterprise SSO (High)
- **SIEM integration** — forward audit logs to Splunk/Elastic (High)
- **Disk progress bar**, **concurrent wipe**, **S3 report upload**, **wipe scheduling**, **REST API**, **Docker Compose deployment** (Medium)
- **SMART health pre-check** (Low)
- **Bootable ISO / PXE** for wiping the running OS disk — the one limitation no software wiper can solve locally; README already documents the DRBL/FOG/WinPE approach but nothing is built
- A recovery-side demo script (see above)

## Timeline note

SIH26149 deadline: **20 September 2026**. Steps 5 (docs) and 7 (demo) are the realistic path to a submission-ready state — the code itself is already functionally complete and tested for all three required modules.
