#!/usr/bin/env bash
# tools/demo_erase.sh
# ------------------------------------------------------------------
# Demo A - "our erase defeats recovery; plain rm does not".
#
#   sudo tools/demo_erase.sh <LOOP> <MNT> <IMG>
#
# Sequence:
#   1. marker present on the raw image           -> FOUND   (baseline)
#   2. plain `rm` a marked file, drop caches      -> still FOUND on image
#   3. `wiperx erase-file` the other marked file  -> file gone
#   4. `wiperx wipe-free` the mount               -> free-space overwritten
#   5. re-scan the raw image for the marker       -> GONE
#   6. `wiperx verify-report` the signed cert     -> VALID
# ------------------------------------------------------------------
set -euo pipefail

LOOP="${1:?usage: demo_erase.sh <LOOP> <MNT> <IMG>}"
MNT="${2:?}"
IMG="${3:?}"
MARKER="SECRET-TOKEN-1234"
ROOT="$(cd "$(dirname "$0")/.." && pwd)"
PY="${WIPERX_PYTHON:-python3}"
WIPERX="$PY -m cli.wiperx_cli"

cd "$ROOT"
scan() { $PY -c "import sys;from core.eraser_file.verify import scan_device_for_marker as s;r=s(sys.argv[1], sys.argv[2].encode());print('  FOUND at offset',r['first_offset']) if r['marker_found'] else print('  not present (scanned %.1f MB)'%(r['bytes_scanned']/1e6))" "$IMG" "$MARKER"; }

echo "=== 1. Baseline: is the marker on the raw image? ==="
sync; scan

echo
echo "=== 2. Plain 'rm' on case42/notes.txt, then drop caches ==="
rm -f "$MNT/case42/notes.txt"
sync; sysctl -q -w vm.drop_caches=3 2>/dev/null || echo 3 > /proc/sys/vm/drop_caches || true
scan
echo "  ^ plain delete removed the directory entry, not the data blocks."

echo
echo "=== 3. wiperx erase-file on case42/keep_me.txt ==="
$WIPERX erase-file "$MNT/case42/keep_me.txt" --yes --operator demo
test ! -e "$MNT/case42/keep_me.txt" && echo "  file is gone"

echo
echo "=== 4. wiperx wipe-free on the mount (overwrite free space) ==="
$WIPERX wipe-free "$MNT" --yes --operator demo
sync; sysctl -q -w vm.drop_caches=3 2>/dev/null || echo 3 > /proc/sys/vm/drop_caches || true

echo
echo "=== 5. Re-scan the raw image for the marker ==="
scan
echo "  ^ expect: not present."

echo
echo "=== 6. Verify the newest signed certificate ==="
CERT="$(ls -t "$ROOT"/reports/*_cert_*.json 2>/dev/null | head -1)"
if [[ -n "${CERT:-}" ]]; then
  $WIPERX verify-report "$CERT"
else
  echo "  (no certificate found in reports/)"
fi

echo
echo "Done. Cleanup:"
echo "  sudo umount ${MNT} && sudo losetup -d ${LOOP} && rm -f ${IMG}"
