cmake_minimum_required(VERSION 3.10)
project(sbc_tpm_app C)

set(CMAKE_C_STANDARD 11)

# -----------------------------------------------------------
# Include / Library paths (TPM2-TSS)
# -----------------------------------------------------------
set(TPM2_TSS_ROOT "/opt/sbc-tpm2-build")

include_directories(
    ${TPM2_TSS_ROOT}/include
    ${CMAKE_SOURCE_DIR}/inc
)

link_directories(
    ${TPM2_TSS_ROOT}/lib
)

# -----------------------------------------------------------
# Source files
# -----------------------------------------------------------
file(GLOB SRC_FILES
    ${CMAKE_SOURCE_DIR}/src/*.c
)

# -----------------------------------------------------------
# Build executable
# -----------------------------------------------------------
add_executable(sbc_tpm ${SRC_FILES})

# -----------------------------------------------------------
# Link TPM2-TSS libraries
#   tss2-esys, tss2-tcti-device 필요
# -----------------------------------------------------------
target_link_libraries(sbc_tpm
    tss2-esys
    tss2-mu
    tss2-rc
    tss2-tcti-device
)

