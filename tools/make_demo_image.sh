#!/usr/bin/env bash
# tools/make_demo_image.sh
# ------------------------------------------------------------------
# Build a loopback ext4 image, mount it, and plant known files - one
# of them carrying the plaintext marker SECRET-TOKEN-1234 that the
# erase demo greps for on the raw image.
#
# Linux only (losetup + mkfs.ext4). Run with sudo.
#
#   sudo tools/make_demo_image.sh [SIZE_MB] [IMG] [MNT]
#
# Outputs the loop device, mount point and image path for demo_erase.sh.
# ------------------------------------------------------------------
set -euo pipefail

SIZE_MB="${1:-512}"
IMG="${2:-/tmp/wiperx_demo.img}"
MNT="${3:-/tmp/wiperx_demo_mnt}"
MARKER="SECRET-TOKEN-1234"

if [[ "$(uname -s)" != "Linux" ]]; then
  echo "This script needs Linux (losetup, mkfs.ext4)." >&2
  exit 1
fi
if [[ $EUID -ne 0 ]]; then
  echo "Run as root (sudo)." >&2
  exit 1
fi

echo "[*] Creating ${SIZE_MB} MB image at ${IMG}"
rm -f "$IMG"
dd if=/dev/zero of="$IMG" bs=1M count="$SIZE_MB" status=none

echo "[*] Formatting ext4"
mkfs.ext4 -q -F "$IMG"

LOOP="$(losetup --find --show "$IMG")"
echo "[*] Attached ${LOOP}"

mkdir -p "$MNT"
mount "$LOOP" "$MNT"
echo "[*] Mounted at ${MNT}"

echo "[*] Planting files"
mkdir -p "$MNT/case42/photos"
printf 'Investigator notes.\nAccess key: %s\nEND\n' "$MARKER" > "$MNT/case42/notes.txt"
printf 'Second copy of the marker: %s\n' "$MARKER"        > "$MNT/case42/keep_me.txt"
head -c 300000 /dev/urandom > "$MNT/case42/photos/img_001.bin"
head -c 150000 /dev/urandom > "$MNT/case42/photos/img_002.bin"
sync

echo
echo "LOOP=${LOOP}"
echo "MNT=${MNT}"
echo "IMG=${IMG}"
echo "MARKER=${MARKER}"
echo
echo "Next:  sudo tools/demo_erase.sh ${LOOP} ${MNT} ${IMG}"
echo "Clean: sudo umount ${MNT} && sudo losetup -d ${LOOP} && rm -f ${IMG}"
