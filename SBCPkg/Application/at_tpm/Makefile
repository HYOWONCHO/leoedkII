# -------------------------------------------------
# Makefile for sbc_tpm_app (Static Library)
# -------------------------------------------------

# Compiler and tools
CC      := gcc
AR      := ar
RANLIB  := ranlib

# C standard and basic compile flags
CSTD    := -std=c11
CFLAGS  := -O2 -Wall -Wextra $(CSTD)

# Project directories
SRC_DIR := src
INC_DIR := inc

# Source and object files
SRCS := $(wildcard $(SRC_DIR)/*.c)
OBJS := $(SRCS:.c=.o)

# Output static library name
LIBNAME := libsbc_tpm.a

ifeq ($(BUILD_DIR),)
BUILD_DIR = $(abspath $(CURDIR))/../../../build
endif
$(info BUILD_DIR = $(BUILD_DIR))

ifeq ($(BUILD), release)
	TARGET_BUILD_PATH = $(BUILD_DIR)/release/lib/at_tpm
endif

ifeq ($(DEBUG), 1)
	DEBUG_FLAGS := -DTPM_DEBUG
	TARGET_BUILD_PATH = $(BUILD_DIR)/release/lib/at_tpm/debug
else ifeq ($(RAWFS), 1)
	TARGET_BUILD_PATH = $(BUILD_DIR)/release/lib/at_tpm/rawfs
endif

$(info TARGET_BUILD_PATH = $(TARGET_BUILD_PATH))


# -------------------------------------------------
# TPM2-TSS installation root
# - Default value can be overridden from command line
#   Example:
#     make TPM2_TSS_ROOT=/usr/local
# -------------------------------------------------
TPM2_TSS_ROOT ?= /opt/sbc-tpm2-build

# -------------------------------------------------
# pkg-config setup
# (Equivalent to extending PKG_CONFIG_PATH in CMake)
# -------------------------------------------------
export PKG_CONFIG_PATH := $(PKG_CONFIG_PATH):\
$(TPM2_TSS_ROOT)/lib/pkgconfig:\
$(TPM2_TSS_ROOT)/lib64/pkgconfig

# We only rely on SYS API and TCTI Loader at build time
PKG_SYS     := tss2-sys
PKG_TCTILDR := tss2-tctildr

# Compiler flags from pkg-config
#PC_CFLAGS := $(shell pkg-config --cflags $(PKG_SYS) $(PKG_TCTILDR) 2>/dev/null)
PC_CFLAGS := $(shell pkg-config --cflags $(PKG_SYS) $(PKG_TCTILDR))

# Add include directories:
#  - TPM2-TSS include paths
#  - Project public headers (inc/)
CFLAGS += $(PC_CFLAGS) -I$(INC_DIR) $(DEBUG_FLAGS)

# -------------------------------------------------
# Build targets
# -------------------------------------------------
.PHONY: all clean distclean show

# Default target
all: $(LIBNAME) $(TARGET_BUILD_PATH) install-lib install-header

install-header:
	@if [ ! -d "$(TARGET_BUILD_PATH)/inc" ]; then 										\
		mkdir -p "$(TARGET_BUILD_PATH)/inc"; 											\
	fi

	install -Dm 0755  inc/*.h $(TARGET_BUILD_PATH)/inc/


install-lib:
	@if [ ! -d "$(TARGET_BUILD_PATH)/lib" ]; then 										\
		mkdir -p "$(TARGET_BUILD_PATH)/lib"; 											\
	fi

	install -Dm 0755  $(LIBNAME) $(TARGET_BUILD_PATH)/lib/

$(TARGET_BUILD_PATH):
	@if [ ! -d "$(TARGET_BUILD_PATH)" ]; then 										\
		mkdir -p "$(TARGET_BUILD_PATH)"; 											\
	fi
	

# Create static library from object files
$(LIBNAME): $(OBJS)
	$(AR) rcs $@ $^
	$(RANLIB) $@

# Compile C source files into object files
%.o: %.c
	$(CC) $(CFLAGS) -c $< -o $@

# -------------------------------------------------
# Utility targets
# -------------------------------------------------

# Print build configuration (debug helper)
show:
	@echo "TPM2_TSS_ROOT   = $(TPM2_TSS_ROOT)"
	@echo "PKG_CONFIG_PATH = $(PKG_CONFIG_PATH)"
	@echo "PC_CFLAGS       = $(PC_CFLAGS)"
	@echo "CFLAGS          = $(CFLAGS)"
	@echo "SRCS            = $(SRCS)"
	@echo "LIBNAME         = $(LIBNAME)"

# Remove object files
clean:
	rm -f $(OBJS)

# Remove all build artifacts
distclean: clean
	rm -f $(LIBNAME)

