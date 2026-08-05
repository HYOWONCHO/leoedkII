#!/usr/bin/env bash
set -euo pipefail

DEVICE="${DEVICE:-/dev/nvme0n1p4}"
OFFSET_HEX="0x100"
OFFSET_DEC=$((OFFSET_HEX))

usage() {
    cat <<EOF
Usage: $0 [0|1]

Description:
  Write 1 byte (0x00 or 0x01) to ${DEVICE} at offset ${OFFSET_HEX}.

Examples:
  $0 1
  $0 0
EOF
    exit 1
}

# Auto elevate to root
if [[ "${EUID}" -ne 0 ]]; then
    exec sudo DEVICE="${DEVICE:-/dev/nvme0n1p4}" "$0" "$@"
fi

# Argument check
if [[ $# -ne 1 ]]; then
    usage
fi

VALUE="$1"

case "${VALUE}" in
    0)
        BYTE='\x00'
        ;;
    1)
        BYTE='\x01'
        ;;
    *)
        echo "[ERROR] Argument must be 0 or 1"
        usage
        ;;
esac

echo "[INFO] Device : ${DEVICE}"
echo "[INFO] Offset : ${OFFSET_HEX} (${OFFSET_DEC})"
echo "[INFO] Value  : ${VALUE}"

# Basic device check
if [[ ! -b "${DEVICE}" ]]; then
    echo "[ERROR] ${DEVICE} is not a valid block device"
    exit 1
fi

# Write exactly 1 byte at the target offset
printf "${BYTE}" | dd of="${DEVICE}" bs=1 seek="${OFFSET_DEC}" conv=notrunc status=none
sync

echo "[INFO] Write completed"

# Verify
echo "[INFO] Verification (16 bytes from offset ${OFFSET_HEX}):"
xxd -g 1 -l 16 -s "${OFFSET_DEC}" "${DEVICE}"
