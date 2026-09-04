#!/bin/sh
# tools/make_demo_image_macos.sh
# macOS equivalent of make_demo_image.sh. Builds a throwaway FAT32 disk image,
# attaches it (WITHOUT mounting the whole disk), mounts the data slice, plants
# marker files, and prints the identifiers demo_erase_macos.sh needs.
#
#   sudo tools/make_demo_image_macos.sh [SIZE_MB] [IMG]
set -eu

SIZE_MB="${1:-512}"
IMG="${2:-/tmp/wiperx_demo.dmg}"
MARKER="SECRET-TOKEN-1234"

[ "$(uname -s)" = "Darwin" ] || { echo "This script needs macOS." >&2; exit 1; }
[ "$(id -u)" -eq 0 ] || { echo "Run as root (sudo)." >&2; exit 1; }

echo "[*] Creating ${SIZE_MB} MB image at ${IMG}"
rm -f "$IMG"
hdiutil create -size "${SIZE_MB}m" -fs "MS-DOS FAT32" -volname WIPERX_DEMO \
  -layout MBRSPUD -type UDIF "$IMG" >/dev/null

echo "[*] Attaching without mounting"
DISK="$(hdiutil attach -nomount "$IMG" | awk '/partition_scheme/{print $1; exit}')"
SLICE="${DISK}s1"
echo "[*] Attached ${DISK} (data slice ${SLICE})"

MNT="/Volumes/WIPERX_DEMO"
diskutil mount -mountPoint "$MNT" "$SLICE" >/dev/null

echo "[*] Planting files"
mkdir -p "$MNT/case42/photos"
printf 'Investigator notes.\nAccess key: %s\nEND\n' "$MARKER" > "$MNT/case42/notes.txt"
printf 'Second copy of the marker: %s\n' "$MARKER"          > "$MNT/case42/keep_me.txt"
head -c 300000 /dev/urandom > "$MNT/case42/photos/img_001.bin"
head -c 150000 /dev/urandom > "$MNT/case42/photos/img_002.bin"
sync

cat <<EOF

DISK=${DISK}
SLICE=${SLICE}
MNT=${MNT}
IMG=${IMG}
MARKER=${MARKER}

Next:  sudo tools/demo_erase_macos.sh ${DISK} ${SLICE} ${MNT} ${IMG}
Clean: diskutil unmountDisk force ${DISK} && hdiutil detach ${DISK} && rm -f ${IMG}
EOF
