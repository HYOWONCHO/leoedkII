#!/usr/bin/env bash

# ========================
#  Color Format
# ========================
RED="\033[31m"
GREEN="\033[32m"
YELLOW="\033[33m"
BLUE="\033[34m"
NC="\033[0m"    # No Color

set -e  # Fail fast

# ========================
#  Function: Install Package If Needed
# ========================
install_pkg() {
    local pkg="$1"

    if rpm -q "$pkg" &> /dev/null; then
        echo -e "${GREEN}[OK]${NC} Package '${pkg}' is already installed."
    else
        echo -e "${YELLOW}[INSTALL]${NC} Installing package '${pkg}' ..."
        echo -e "${BLUE}CMD:${NC} sudo dnf install -y ${pkg}"
        sudo dnf install -y "$pkg"
    fi
}

echo -e "${BLUE}=====================================================${NC}"
echo -e "${GREEN}Checking & Enabling CRB Repository (required for -devel pkgs)${NC}"
echo -e "${BLUE}=====================================================${NC}"

sudo dnf repolist | grep -qi crb || {
    echo -e "${YELLOW}[INFO]${NC} CRB repo not enabled. Enabling now..."
    sudo dnf config-manager --set-enabled crb
    sudo dnf makecache -q
}


echo -e "${BLUE}=====================================================${NC}"
echo -e "${GREEN}Installing base autotools packages${NC}"
echo -e "${BLUE}=====================================================${NC}"

install_pkg libtool
install_pkg automake
install_pkg autoconf
install_pkg autoconf-archive


echo -e "${BLUE}=====================================================${NC}"
echo -e "${GREEN}Installing tpm2-tss build dependencies (dnf builddep)${NC}"
echo -e "${BLUE}=====================================================${NC}"

echo -e "${YELLOW}[INFO]${NC} Running: sudo dnf builddep -y tpm2-tss"
sudo dnf builddep -y tpm2-tss || echo -e "${YELLOW}[WARN] builddep failed (some packages may be missing)${NC}"


echo -e "${BLUE}=====================================================${NC}"
echo -e "${GREEN}Installing additional required dependencies (OpenSSL/json-c/curl/uuid)${NC}"
echo -e "${BLUE}=====================================================${NC}"

# IMPORTANT: tpm2-tss requires these devel packages explicitly
install_pkg openssl-devel
install_pkg json-c
install_pkg json-c-devel
install_pkg curl
install_pkg curl-devel
install_pkg libuuid-devel


echo -e "${BLUE}=====================================================${NC}"
echo -e "${GREEN}Validating pkg-config entries${NC}"
echo -e "${BLUE}=====================================================${NC}"

export PKG_CONFIG_PATH=/usr/lib64/pkgconfig:$PKG_CONFIG_PATH

echo -e "${YELLOW}json-c version   :${NC} $(pkg-config --modversion json-c 2>/dev/null || echo NOT FOUND)"
echo -e "${YELLOW}libcurl version  :${NC} $(pkg-config --modversion libcurl 2>/dev/null || echo NOT FOUND)"
echo -e "${YELLOW}uuid version     :${NC} $(pkg-config --modversion uuid 2>/dev/null || echo NOT FOUND)"
echo -e "${YELLOW}OpenSSL version  :${NC} $(openssl version 2>/dev/null || echo NOT FOUND)"


echo -e "${GREEN}=====================================================${NC}"
echo -e "${GREEN}DONE: All required packages for TPM2-TSS build installed successfully!${NC}"
echo -e "${GREEN}=====================================================${NC}"

