#!/usr/bin/env bash

# ========================
#  Color Format
# ========================
RED="\033[31m"
GREEN="\033[32m"
YELLOW="\033[33m"
BLUE="\033[34m"
NC="\033[0m"

set -e  # Fail on error

# ========================
#  Function: Install Package If Needed (Ubuntu)
# ========================
install_pkg() {
    local pkg="$1"

    if dpkg -l | grep -q "^ii\s\+$pkg\s"; then
        echo -e "${GREEN}[OK]${NC} Package '${pkg}' already installed."
    else
        echo -e "${YELLOW}[INSTALL]${NC} Installing '${pkg}' ..."
        echo -e "${BLUE}CMD:${NC} sudo apt-get install -y ${pkg}"
        sudo apt-get install -y "$pkg"
    fi
}

echo -e "${BLUE}=====================================================${NC}"
echo -e "${GREEN}Installing autotools packages for Ubuntu${NC}"
echo -e "${BLUE}=====================================================${NC}"

install_pkg autoconf
install_pkg automake
install_pkg libtool
install_pkg autoconf-archive


echo -e "${BLUE}=====================================================${NC}"
echo -e "${GREEN}Installing tpm2-tss build dependencies (Ubuntu equivalent)${NC}"
echo -e "${BLUE}=====================================================${NC}"

# Equivalent dependencies to dnf builddep tpm2-tss
install_pkg pkg-config
install_pkg gcc
install_pkg g++
install_pkg libssl-dev
install_pkg libcurl4-openssl-dev
install_pkg libjson-c-dev
install_pkg libgcrypt20-dev
install_pkg libcmocka-dev
install_pkg libgmp-dev
install_pkg liburiparser-dev
install_pkg libsqlite3-dev
install_pkg libltdl-dev
install_pkg uuid-dev     # same as libuuid-devel in RedHat


echo -e "${GREEN}=====================================================${NC}"
echo -e "${GREEN}DONE: All required packages for tpm2-tss build installed on Ubuntu!${NC}"
echo -e "${GREEN}=====================================================${NC}"

