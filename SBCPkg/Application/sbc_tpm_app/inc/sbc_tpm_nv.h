#ifndef SBC_TPM_NV_MANAGER_H
#define SBC_TPM_NV_MANAGER_H

#include <stdint.h>
#include <stddef.h>
#include <tss2/tss2_sys.h>
#include <tss2/tss2_tctildr.h>

#ifdef __cplusplus
extern "C" {
#endif

/* ========================================================================================
 *  SBCStatus – Unified return codes used by the NV Manager
 * ======================================================================================== */
typedef enum {
    SBC_OK = 0,             /* Operation successful */
    SBC_FAIL,               /* General failure */
    SBC_TPM_ERR,            /* TPM returned an error */
    SBC_ARG_ERR,            /* Invalid argument */
    SBC_MEM_ERR,            /* Memory allocation error */
    SBC_NV_NOT_FOUND,       /* NV index does not exist */
    SBC_NV_ALREADY_DEFINED, /* NV index already defined */
    SBC_NV_SIZE_MISMATCH,   /* Data size mismatch */
    SBC_CRC_MISMATCH        /* CRC verification failed */
} SBCStatus;

/* ========================================================================================
 *  SBC_TPM_CTX – TPM system/tcti context bundle
 * ======================================================================================== */
typedef struct {
    TSS2_TCTI_CONTEXT *tcti;   /* TCTI context */
    TSS2_SYS_CONTEXT  *sys;    /* ESAPI system context */
} SBC_TPM_CTX;

/* ========================================================================================
 *  SBC_NV_SLOT – NV index descriptor (used for NV table management)
 * ======================================================================================== */
typedef struct {
    TPMI_RH_NV_INDEX index;  /* NV index */
    uint16_t         size;   /* NV data size */
    const char      *name;   /* Logical name for identification */
} SBC_NV_SLOT;

/* ========================================================================================
 *  TPM Initialization / Finalization APIs
 * ======================================================================================== */

/**
 * @brief Initialize TPM (TCTI loader + ESAPI system context).
 *
 * @param ctx       Pointer to target TPM context structure.
 * @param tcti_conf TCTI configuration string ("device:/dev/tpm0").
 *
 * @return SBCStatus
 */
SBCStatus SBC_TpmInit(SBC_TPM_CTX *ctx, const char *tcti_conf);

/**
 * @brief Release TCTI + ESAPI contexts.
 */
void SBC_TpmFinish(SBC_TPM_CTX *ctx);

/* ========================================================================================
 *  NV Index Management APIs
 * ======================================================================================== */

/**
 * @brief Check whether an NV index exists.
 *
 * @param ctx   TPM context pointer.
 * @param index NV index to check.
 *
 * @return 1 = exists, 0 = not exist, <0 = error.
 */
int SBC_NvExists(SBC_TPM_CTX *ctx, TPMI_RH_NV_INDEX index);

/**
 * @brief Create (define) an NV index with owner+auth read/write attributes.
 *
 * @param ctx   TPM context.
 * @param index NV index to define.
 * @param size  NV data size.
 *
 * @return SBCStatus
 */
SBCStatus SBC_NvDefine(SBC_TPM_CTX *ctx,
                       TPMI_RH_NV_INDEX index,
                       uint16_t size);

/**
 * @brief Remove (undefine) an NV index.
 *
 * @param ctx   TPM context.
 * @param index NV index to undefine.
 *
 * @return SBCStatus
 */
SBCStatus SBC_NvUndefine(SBC_TPM_CTX *ctx, TPMI_RH_NV_INDEX index);

/**
 * @brief Ensure that an NV index exists; if not, define it.
 *
 * @param ctx   TPM context.
 * @param index NV index to verify/create.
 * @param size  Expected NV size.
 *
 * @return SBCStatus
 */
SBCStatus SBC_NvEnsureDefined(SBC_TPM_CTX *ctx,
                              TPMI_RH_NV_INDEX index,
                              uint16_t size);

/* ========================================================================================
 *  NV Read / Write APIs
 * ======================================================================================== */

/**
 * @brief Write data into NV with CRC verification.
 *
 * @param ctx          TPM context.
 * @param slot         Pointer to NV slot descriptor.
 * @param data         Data buffer to write.
 * @param size         Data size (must match slot->size).
 * @param expected_crc If non-zero, verify CRC32 before writing.
 *
 * @return SBCStatus
 */
SBCStatus SBC_NvWriteChecked(SBC_TPM_CTX *ctx,
                             const SBC_NV_SLOT *slot,
                             const uint8_t *data,
                             uint16_t size,
                             uint32_t expected_crc);

/**
 * @brief Read NV data and print it using colored hexdump format.
 *
 * @param ctx  TPM context.
 * @param slot NV slot descriptor.
 *
 * @return SBCStatus
 */
SBCStatus SBC_NvReadHexdump(SBC_TPM_CTX *ctx,
                            const SBC_NV_SLOT *slot);

/**
 * @brief Find an NV slot in the NV table by its logical name.
 *
 * @param name Name of the NV slot ("KEY1", "CERT1", etc.)
 *
 * @return Pointer to slot, or NULL if not found.
 */
const SBC_NV_SLOT* SBC_NvFindSlotByName(const char *name);

/* ========================================================================================
 *  CRC / Hexdump Utilities
 * ======================================================================================== */

/**
 * @brief Compute CRC32 value of a buffer.
 *
 * @param buf Pointer to data.
 * @param len Data length.
 *
 * @return CRC32 value (polynomial: 0xEDB88320)
 */
uint32_t crc32_calc(const uint8_t *buf, size_t len);

/**
 * @brief Print data in colored hexdump format.
 *
 * @param data Data buffer.
 * @param size Data size.
 */
void hexdump_color(const uint8_t *data, size_t size);

#ifdef __cplusplus
}
#endif

#endif /* SBC_TPM_NV_MANAGER_H */

