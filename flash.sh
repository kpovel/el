#!/bin/bash
set -e
UF2=build/grid_monitor.uf2
[ -f "$UF2" ] || { echo "$UF2 not found — run make first"; exit 1; }

DEV=$(lsblk -rno NAME,LABEL | awk '$2=="RP2350"{print "/dev/"$1; exit}')
[ -n "$DEV" ] || { echo "RP2350 not found. Hold BOOTSEL + plug USB."; exit 1; }

MNT=$(lsblk -rno MOUNTPOINT "$DEV" | head -1)
if [ -z "$MNT" ]; then
    MNT="/tmp/rp2350"
    mkdir -p "$MNT"
    sudo mount "$DEV" "$MNT"
    echo "Mounted $DEV at $MNT"
    UNMOUNT=1
fi

cp "$UF2" "$MNT/"
sync
[ "${UNMOUNT:-0}" = 1 ] && sudo umount "$MNT"
echo "Flashed. Pico will reboot."
