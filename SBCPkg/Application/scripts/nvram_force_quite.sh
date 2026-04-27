#!/usr/bin/env bash

set -euo pipefail

VAR_NAME="d4fe1500-6c3c-4ad5-9ea1-22d2976c56d9-SBC_ForcedFaultRejct"

# root 권한 자동 승격
if [[ "${EUID}" -ne 0 ]]; then
    exec sudo "$0" "$@"
fi

# 인자 체크
if [[ $# -ne 1 ]]; then
    echo "Usae: $0 [0|1]"
    exit 1
fi

VALUE="$1"

if [[ "${VALUE}" != "0" && "${VALUE}" != "1" ]]; then
    echo "[ERROR] Value must be 0 or 1"
    exit 1
fi

echo "[INFO] Set value = ${VALUE}"

# efivar 설치 (OS 자동 감지)
if ! command -v efivar >/dev/null 2>&1; then
    echo "[INFO] Installin efivar..."

    if [[ -f /etc/redhat-release ]]; then
        dnf install -y efivar
    elif [[ -f /etc/debian_version ]]; then
        apt update
        apt install -y efivar
    else
        echo "[ERROR] Unsupported OS"
        exit 1
    fi
fi

# UEFI 체크
if [[ ! -d /sys/firmware/efi ]]; then
    echo "[ERROR] Not runnin in UEFI mode"
    exit 1
fi

#  현재 값 확인
echo "[INFO] Current NVRAM value:"
efivar -n ${VAR_NAME} -p || true

#  값 쓰기
BIN_FILE="/tmp/sbc_nvram.bin"

if [[ "${VALUE}" == "1" ]]; then
    printf "\x07\x00\x00\x00\x01" > "${BIN_FILE}"
else
    printf "\x07\x00\x00\x00\x00" > "${BIN_FILE}"
fi

efivar -n ${VAR_NAME} -w -f "${BIN_FILE}"

#  결과 확인
echo "[INFO] Updated NVRAM value:"
efivar -n ${VAR_NAME} -p

echo "[INFO] Done"

# Usae
#./nvram_set.sh 1   # enable
#./nvram_set.sh 0   # disable
