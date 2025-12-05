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
sudo dnf builddep -y tpm2-tss


echo -e "${BLUE}=====================================================${NC}"
echo -e "${GREEN}Installing libuuid-devel (required for tpm2-tss >= 4.0.0)${NC}"
echo -e "${BLUE}=====================================================${NC}"

install_pkg libuuid-devel


echo -e "${GREEN}=====================================================${NC}"
echo -e "${GREEN}DONE: All required packages for tpm2-tss build installed!${NC}"
echo -e "${GREEN}=====================================================${NC}"

