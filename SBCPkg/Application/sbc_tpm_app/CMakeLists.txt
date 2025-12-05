cmake_minimum_required(VERSION 3.10)
project(sbc_tpm_app C)

set(CMAKE_C_STANDARD 11)

set(TPM2_TSS_ROOT "/opt/sbc-tpm2-build")

# ---------------------------------------------
# pkg-config integration
# ---------------------------------------------
find_package(PkgConfig REQUIRED)

set(ENV{PKG_CONFIG_PATH}
    "${TPM2_TSS_ROOT}/lib/pkgconfig:${TPM2_TSS_ROOT}/lib64/pkgconfig"
)

pkg_check_modules(TSS2_ESYS REQUIRED tss2-esys)
pkg_check_modules(TSS2_SYS REQUIRED tss2-sys)
pkg_check_modules(TSS2_TCTI REQUIRED tss2-tcti-device)

include_directories(
    ${TSS2_ESYS_INCLUDE_DIRS}
    ${TSS2_SYS_INCLUDE_DIRS}
    ${CMAKE_SOURCE_DIR}/inc
)

link_directories(
    ${TSS2_ESYS_LIBRARY_DIRS}
    ${TSS2_SYS_LIBRARY_DIRS}
    ${TSS2_TCTI_LIBRARY_DIRS}
)

# ---------------------------------------------
# src files
# ---------------------------------------------
file(GLOB SRC_FILES ${CMAKE_SOURCE_DIR}/src/*.c)

add_executable(sbc_tpm ${SRC_FILES})

#target_link_libraries(sbc_tpm
#    ${TSS2_ESYS_LIBRARIES}
#    ${TSS2_SYS_LIBRARIES}
#    ${TSS2_TCTI_LIBRARIES}
#)


target_link_libraries(sbc_tpm
    tss2-esys
    tss2-sys
    tss2-mu
    tss2-rc
    tss2-tcti-device
    tss2-tctildr        # ← 반드시 필요!
)

