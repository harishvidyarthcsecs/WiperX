# wiperx/core/eraser_file/__init__.py
"""
Secure File & Folder Eraser (Module 2)
--------------------------------------
Selective secure deletion of files and folders with residual-trace
removal, batch operation, verification, and signed audit reporting.

Submodules
    file_shredder  : per-file overwrite + rename-chain + unlink   (Codex-owned)
    batch          : recursive walk + worker pool + aggregation   (Codex-owned)
    trace_scrubber : free-space fill, fstrim, slack zeroing        (Claude-owned)
    verify         : raw read-back confirmation of destruction     (Claude-owned)

Neither the CLI nor Flask contains erase logic — they call this package.
Standards mapping: NIST SP 800-88 Rev.1 "Clear" for logical media.
"""
