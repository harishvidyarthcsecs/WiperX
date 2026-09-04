#!/bin/sh
# tools/demo_erase_macos.sh
# macOS "Demo A": our erase defeats recovery; plain rm does not.
#
#   sudo tools/demo_erase_macos.sh <DISK> <SLICE> <MNT> <IMG>
# (identifiers come from make_demo_image_macos.sh)
set -eu

DISK="${1:?usage: demo_erase_macos.sh <DISK> <SLICE> <MNT> <IMG>}"
SLICE="${2:?}"
MNT="${3:?}"
IMG="${4:?}"
MARKER="SECRET-TOKEN-1234"
ROOT="$(cd "$(dirname "$0")/.." && pwd)"
PY="${WIPERX_PYTHON:-python3}"
WIPERX="$PY -m cli.wiperx_cli"
cd "$ROOT"

scan() {
  "$PY" - "$IMG" "$MARKER" <<'PYEOF'
import sys
from core.eraser_file.verify import scan_device_for_marker as s
r = s(sys.argv[1], sys.argv[2].encode())
print("  FOUND at offset", r["first_offset"]) if r["marker_found"] else \
    print("  not present (scanned %.1f MB)" % (r["bytes_scanned"] / 1e6))
PYEOF
}

echo "=== 1. Baseline: marker on the raw image? ==="
sync; scan

echo
echo "=== 2. Plain 'rm' on case42/notes.txt, then drop the cache ==="
rm -f "$MNT/case42/notes.txt"
sync; purge 2>/dev/null || true
scan
echo "  ^ plain delete removed the directory entry, not the data blocks."

echo
echo "=== 3. wiperx erase-file on case42/keep_me.txt ==="
$WIPERX erase-file "$MNT/case42/keep_me.txt" --yes --operator demo
[ ! -e "$MNT/case42/keep_me.txt" ] && echo "  file is gone"

echo
echo "=== 4. wiperx wipe-free on the mount ==="
$WIPERX wipe-free "$MNT" --yes --operator demo
sync; purge 2>/dev/null || true

echo
echo "=== 5. Re-scan the raw image for the marker ==="
scan
echo "  ^ expect: not present."

echo
echo "=== 6. Verify the newest signed certificate ==="
CERT="$(ls -t "$ROOT"/reports/*/erase_*.json "$ROOT"/reports/*_cert_*.json 2>/dev/null | head -1)"
if [ -n "${CERT:-}" ]; then
  $WIPERX verify-report "$CERT"
else
  echo "  (no certificate found in reports/)"
fi

echo
echo "Done. Cleanup:"
echo "  diskutil unmountDisk force ${DISK} && hdiutil detach ${DISK} && rm -f ${IMG}"
