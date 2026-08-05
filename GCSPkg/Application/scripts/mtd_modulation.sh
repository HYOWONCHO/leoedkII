#!/usr/bin/env bash
set -euo pipefail

DEVICE="${1:-/dev/nvme0n1p4}"
OFFSET_HEX="${2:-0x18206242}"

BYTE1='\xD4'
BYTE2='\xC3'
BYTE3='\xB2'
BYTE4='\xA1'

if [[ "${EUID}" -ne 0 ]]; then
    exec sudo "$0" "$@"
fi

if [[ ! -b "${DEVICE}" ]]; then
    echo "[ERROR] Block device not found: ${DEVICE}"
    exit 1
fi

OFFSET_DEC=$((OFFSET_HEX))

echo "[INFO] Device     : ${DEVICE}"
echo "[INFO] Offset(hex): ${OFFSET_HEX}"
echo "[INFO] Offset(dec): ${OFFSET_DEC}"
echo "[INFO] Write bytes: D4 C3 B2 A1"

printf "${BYTE1}${BYTE2}${BYTE3}${BYTE4}" \
    | dd of="${DEVICE}" bs=1 seek="${OFFSET_DEC}" conv=notrunc status=none

sync

echo "[INFO] Verify:"
xxd -g 1 -l 16 -s "${OFFSET_DEC}" "${DEVICE}"
