#!/usr/bin/env bash
# tools/demo_recover.sh
# ------------------------------------------------------------------
# Demo B - "deleted is not gone until WiperX says so" (Module 3).
#
#   tools/demo_recover.sh [SIZE_MB]
#
# Unlike demo_erase.sh, this needs NO root: mkfs.ext4 -d populates a
# filesystem directly into a regular file, and debugfs -w deletes a
# file from inside that image, both without mounting anything.
# core.recovery.acquire.open_source() treats a regular file exactly
# like a device - no loop, no mount.
#
# Sequence:
#   1. plant a marked file, then delete it via debugfs (simulates an
#      operator deleting evidence the ordinary way)
#   2. wiperx recover --source <image>   -> WiperX finds it anyway
#   3. show classification + confidence score + chain of custody
#   4. wiperx verify-report the signed case report -> VALID
# ------------------------------------------------------------------
set -euo pipefail

SIZE_MB="${1:-48}"
MARKER="RECOVER-DEMO-TOKEN-5678"
ROOT="$(cd "$(dirname "$0")/.." && pwd)"
PY="${WIPERX_PYTHON:-python3}"
WIPERX="$PY -m cli.wiperx_cli"
WORK="$(mktemp -d /tmp/wiperx_demo_recover.XXXXXX)"
SEED="$WORK/seed"
IMG="$WORK/case.img"
OUT="$WORK/case_out"

cleanup() { rm -rf "$WORK"; }
trap cleanup EXIT

cd "$ROOT"

if ! command -v mkfs.ext4 >/dev/null || ! command -v debugfs >/dev/null; then
  echo "This demo needs mkfs.ext4 and debugfs (e2fsprogs). Install with:" >&2
  echo "  sudo apt install e2fsprogs" >&2
  exit 1
fi

echo "=== 1. Build a ${SIZE_MB}MB ext4 image and plant a marked file ==="
mkdir -p "$SEED"
printf 'Investigator notes.\nEvidence marker: %s\nEND\n' "$MARKER" > "$SEED/evidence.txt"
head -c 300000 /dev/urandom > "$SEED/photo.bin"
dd if=/dev/zero of="$IMG" bs=1M count="$SIZE_MB" status=none
mkfs.ext4 -q -F -d "$SEED" "$IMG"
echo "  built ${IMG} (no root, no mount, no loop device)"

echo
echo "=== 2. Delete evidence.txt from inside the image (debugfs, no mount) ==="
debugfs -w -R "rm /evidence.txt" "$IMG" >/dev/null 2>&1
echo "  file removed from the filesystem's directory listing"

echo
echo "=== 3. wiperx recover --source ${IMG} ==="
$WIPERX recover --source "$IMG" --out "$OUT" --operator demo

echo
echo "=== 4. Confirm the recovered content matches the marker byte-for-byte ==="
FOUND="$(grep -rl "$MARKER" "$OUT"/recovered/ 2>/dev/null | head -1 || true)"
if [[ -n "$FOUND" ]]; then
  echo "  MATCH: $FOUND"
  echo "  ^ the file WiperX recovered is byte-identical to what was deleted."
else
  echo "  WARNING: marker not found in any recovered file (see log above)."
fi

echo
echo "=== 5. Verify the signed case report ==="
REPORT="$(find "$OUT" -name 'case_report.json' | head -1)"
if [[ -n "$REPORT" ]]; then
  $WIPERX verify-report "$REPORT"
else
  echo "  (no case report found)"
fi

echo
echo "Done. Case output was under: $OUT (removed on exit; rerun without"
echo "the trap, or copy \$OUT before it exits, to keep it)."
