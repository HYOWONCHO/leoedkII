#!/usr/bin/env bash

# =====================================================
#  Color
# =====================================================
RED="\033[31m"
GREEN="\033[32m"
YELLOW="\033[33m"
BLUE="\033[34m"
NC="\033[0m"

# =====================================================
#  sudo 자동 판단
# =====================================================
if [ "$(id -u)" -eq 0 ]; then
    SUDO=""
else
    SUDO="sudo"
fi

PREFIX="/opt/sbc-tpm2-tss"
REPO="https://github.com/tpm2-software/tpm2-tss.git"

echo -e "${BLUE}=================================================${NC}"
echo -e "${GREEN}   TPM2-TSS Build Script Started                ${NC}"
echo -e "${BLUE}=================================================${NC}"

# =====================================================
#  Clone repository (fresh)
# =====================================================
if [ -d "tpm2-tss" ]; then
    echo -e "${YELLOW}[INFO] Existing tpm2-tss directory detected, removing...${NC}"
    rm -rf tpm2-tss
fi

echo -e "${GREEN}[CLONE]${NC} git clone ${REPO}"
if ! git clone "$REPO"; then
    echo -e "${RED}[ERROR] git clone failed. Aborting.${NC}"
    exit 1
fi

cd tpm2-tss

# =====================================================
#  Create install prefix directory if missing
# =====================================================
if [ ! -d "$PREFIX" ]; then
    echo -e "${YELLOW}[INFO] Creating prefix directory: $PREFIX${NC}"
    if ! $SUDO mkdir -p "$PREFIX"; then
        echo -e "${RED}[ERROR] Failed to create $PREFIX. Aborting.${NC}"
        exit 1
    fi
fi

# =====================================================
#  Bootstrap
# =====================================================
echo -e "${GREEN}[BOOTSTRAP] Running bootstrap...${NC}"
if ! ./bootstrap 2>/dev/null && ! ./autogen.sh 2>/dev/null; then
    echo -e "${RED}[ERROR] bootstrap/autogen failed.${NC}"
    exit 1
fi

# =====================================================
#  Configure (가장 핵심 포인트)
# =====================================================
echo -e "${GREEN}[CONFIGURE] prefix=${PREFIX}${NC}"
echo -e "${GREEN}[CONFIGURE] Enabling ESAPI, SYSAPI, TCTI, RC, MU${NC}"

if ! ./configure \
    --prefix="$PREFIX" \
    --enable-esapi \
    --enable-sysapi \
    --enable-tcti-all \
    --enable-rc \
    --enable-mu \
    --enable-unit \
    --with-tctidefaultmodule=device \
    --with-udevrulesdir=/etc/udev/rules.d \
; then
    echo -e "${RED}[ERROR] configure failed. Aborting.${NC}"
    exit 1
fi

echo -e "${GREEN}[OK] configure success.${NC}"

# =====================================================
#  Build (make)
# =====================================================
echo -e "${GREEN}[MAKE] Building tpm2-tss...${NC}"

if ! make -j"$(nproc)"; then
    echo -e "${RED}[ERROR] make failed. Aborting.${NC}"
    exit 1
fi

echo -e "${GREEN}[OK] make success.${NC}"

# =====================================================
#  Install
# =====================================================
echo -e "${GREEN}[INSTALL] Installing tpm2-tss...${NC}"

if ! $SUDO make install; then
    echo -e "${RED}[ERROR] make install failed. Aborting.${NC}"
    exit 1
fi

echo -e "${GREEN}[OK] make install success.${NC}"

# =====================================================
#  ldconfig
# =====================================================
echo -e "${GREEN}[LDCONFIG] Updating shared library cache...${NC}"

if ! $SUDO ldconfig; then
    echo -e "${RED}[ERROR] ldconfig failed.${NC}"
    exit 1
fi

echo -e "${GREEN}=================================================${NC}"
echo -e "${GREEN} TPM2-TSS Build & Install Completed Successfully!${NC}"
echo -e "${GREEN} Installed to: ${PREFIX}${NC}"
echo -e "${GREEN}=================================================${NC}"

