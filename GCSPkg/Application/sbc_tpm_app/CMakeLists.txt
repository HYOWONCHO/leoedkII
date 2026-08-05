cmake_minimum_required(VERSION 3.10)
project(sbc_tpm_app C)

set(CMAKE_C_STANDARD 11)

set(TPM2_TSS_ROOT "/opt/sbc-tpm2-build")

# ---------------------------------------------
# pkg-config integration
# ---------------------------------------------
find_package(PkgConfig REQUIRED)

# Extend PKG_CONFIG_PATH (append)
set(ENV{PKG_CONFIG_PATH}
    "$ENV{PKG_CONFIG_PATH}:${TPM2_TSS_ROOT}/lib/pkgconfig:${TPM2_TSS_ROOT}/lib64/pkgconfig"
)

# We only use SYS API + TCTI Loader + RC helpers
pkg_check_modules(TSS2_SYS REQUIRED tss2-sys)
pkg_check_modules(TSS2_TCTILDR REQUIRED tss2-tctildr)

include_directories(
    ${TSS2_SYS_INCLUDE_DIRS}
    ${CMAKE_SOURCE_DIR}/inc
)

link_directories(
    ${TSS2_SYS_LIBRARY_DIRS}
    ${TSS2_TCTILDR_LIBRARY_DIRS}
)

# ---------------------------------------------
# source files
# ---------------------------------------------
file(GLOB SRC_FILES ${CMAKE_SOURCE_DIR}/src/*.c)

add_executable(sbc_tpm ${SRC_FILES})

# ---------------------------------------------
# TPM2-TSS libraries
# ---------------------------------------------
target_link_libraries(sbc_tpm
    tss2-sys
    tss2-esys
    tss2-mu
    tss2-tctildr
    tss2-tcti-device
    tss2-rc       # <-- 반드시 마지막 또는 거의 마지막에 위치
)



