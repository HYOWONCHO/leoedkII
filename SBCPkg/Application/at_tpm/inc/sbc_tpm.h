#ifndef SBC_TPM_H
#define SBC_TPM_H

#include <stdint.h>
#include <tss2/tss2_sys.h>
#include <tss2/tss2_tctildr.h>

/**
 * @brief SBCStatus uses uint32_t to be compatible with TPM2_RC.
 *
 * 0x00000000         : Success (SBC_OK)
 * 0x0000xxxx         : TPM2_RC_xxxx (TPM error codes, returned as-is)
 * 0xFFFFxxxx         : SBC internal errors
 */
typedef uint32_t SBCStatus;

/* Success */
#define SBC_OK               0x00000000u

/* Internal (non-TPM) errors: use high range to avoid TPM RC collision */
#define SBC_ARG_ERR          0xFFFF0001u
#define SBC_MEM_ERR          0xFFFF0002u
#define SBC_NV_NOT_FOUND     0xFFFF0003u
#define SBC_SIZE_ERR         0xFFFF0004u
#define SBC_CRC_ERR          0xFFFF0005u
#define SBC_FAIL             0xFFFF0006u

/* Helper macro to check if code is TPM RC or SBC internal code */
#define SBC_IS_TPM_RC(rc)    (((rc) & 0xFFFF0000u) == 0)

/**
 * @brief TPM context wrapper used by SBC TPM utilities.
 */
typedef struct {
    TSS2_TCTI_CONTEXT *tcti;
    TSS2_SYS_CONTEXT  *sys;
} SBC_TPM_CTX;

/**
 * @brief Initialize TPM context using TCTI loader.
 *
 * @param ctx       Pointer to SBC_TPM_CTX.
 * @param tcti_conf TCTI config string (e.g. "device:/dev/tpm0").
 *                  If NULL, default "device:/dev/tpmrm0" is used.
 *
 * @return SBC_OK on success, TPM2_RC_xxxx or SBC_xxxx on error.
 */
SBCStatus SBC_TpmInit(SBC_TPM_CTX *ctx, const char *tcti_conf);

/**
 * @brief Finalize TPM context and free resources.
 */
void SBC_TpmFinish(SBC_TPM_CTX *ctx);

#endif /* SBC_TPM_H */

