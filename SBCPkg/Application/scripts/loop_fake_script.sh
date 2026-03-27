#!/usr/bin/env bash
set -euo pipefail

IMG=fake_blkdev.img

dd if=/dev/zero of=${IMG} bs=1M count=10

LOOP=$(sudo losetup -f --show ${IMG})

echo "[INFO] Loop device: ${LOOP}"

sudo DEVICE=${LOOP} ./set_nvme_flag.sh 1

xxd -g 1 -l 16 -s $((0x100)) ${LOOP}

sudo losetup -d ${LOOP}
