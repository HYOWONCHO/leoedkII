# TPM2 TSS (tpm2-tss) Installation Guide

This guide explains how to install **TPM2-TSS (TSS2)** and related developer packages
on **Ubuntu** and **Rocky Linux**.  
These libraries are required when building applications that use TPM devices
(`/dev/tpm0`, `/dev/tpmrm0`) for cryptographic operations such as **TPM Hash**,  
**PCR Read/Extend**, **NV read/write**, etc.

---

## 📦 Required Components

| Package | Description |
|--------|-------------|
| **tpm2-tss** | Core TPM2 user-space library (TSS2) |
| **tpm2-tools** | TPM2 CLI tools (PCR, Hash, NV, Quote…) |
| **tss2-devel / libtss2-dev** | Development headers & libraries |
| **tcti-device / tcti-mssim** | TCTI layer for `/dev/tpm0` and simulator |

---

# 🐧 1. Ubuntu Installation (20.04 / 22.04 / 24.04)

Ubuntu provides official TPM2 packages via APT.

### Install TPM2 Libraries
``````
```bash
sudo apt update
sudo apt install -y tpm2-tss \
                    tpm2-tools \
                    libtss2-dev \
                    libtss2-esys-dev \
                    libtss2-mu-dev \
                    libtss2-tcti-device-dev \
                    libtss2-tcti-mssim-dev


### Verify Installation
pkg-config --cflags tss2-sys
pkg-config --libs tss2-sys


# Rocky LInux Insstallation ( for 8.x / 9.x ) 



