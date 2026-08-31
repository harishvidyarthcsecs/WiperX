# wiperx/core/recovery/__init__.py
"""
Advanced File Carving & Recovery (Module 3)
------------------------------------------
Recover deleted / lost files from a block device or forensic image using
two independent paths:

  fs_recover   : filesystem-aware undelete (pytsk3 / Sleuth Kit) - recovers
                 files still referenced by orphaned inode / MFT records,
                 with original names, paths and timestamps.  (Claude-owned)
  carver_*     : metadata-free carving - scan raw bytes for file headers,
                 carve to a validated footer / structural end.  (Codex-owned)

Every run is evidential:
  - the source is opened read-only and never written to;
  - the whole source is SHA-256 hashed into the case manifest;
  - all output goes to a separate cases/<case-id>/ directory;
  - the case report is deterministic and Ed25519-signed.

Submodules
    acquire          : read-only Source + Case (hashing, case dir, read log)  (Claude)
    signatures       : magic-number table                                    (Codex)
    carver_header    : header -> footer / max-size carving                    (Codex)
    carver_structure : structural EOF refinement (PNG/JPEG/ZIP/GIF/PDF/MP4)   (Codex)
    carver_fragment  : JPEG bifragment gap carving                           (Codex)
    classify         : content-type classification                           (Codex)
    validate         : per-type file validators                              (Codex)
    fs_recover       : pytsk3 / tsk-CLI undelete                             (Claude)
    confidence       : composite recovery-confidence score                   (Claude)
    case_report      : signed forensic case report                           (Claude)
    service          : orchestration entrypoint                              (Claude)
"""
