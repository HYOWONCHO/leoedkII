#ifndef SBC_TPM_NV_H
#define SBC_TPM_NV_H

#include <stdint.h>
#include <tss2/tss2_sys.h>

#include "sbc_tpm.h"

/**
 * @brief NV slot descriptor for logical mapping.
 */
typedef struct {
    TPMI_RH_NV_INDEX index;
    uint16_t         size;
    const char      *name;   /* logical name (e.g. "KEY1", "CERT1") */
} SBC_NV_SLOT;

/**
 * @brief Check whether a TPM NV index exists.
 *
 * @return 1 = exists, 0 = not exist, -1 = error.
 */
int SBC_NvExists(SBC_TPM_CTX *ctx, TPMI_RH_NV_INDEX index);

/**
 * @brief Ensure that the given NV index is defined with the expected size.
 *
 * If the NV index does not exist, this function will define it.
 *
 * @return SBC_OK or TPM2_RC_xxxx or SBC_xxxx.
 */
SBCStatus SBC_NvEnsureDefined(SBC_TPM_CTX *ctx,
                              TPMI_RH_NV_INDEX index,
                              uint16_t size);

/**
 * @brief Write data into NV after CRC check.
 *
 * @param ctx          TPM context.
 * @param slot         NV slot descriptor (index, size, name).
 * @param data         Input data buffer.
 * @param size         Size of data (must match slot->size).
 * @param expected_crc If non-zero, compare with computed CRC and fail on mismatch.
 *
 * @return SBC_OK, TPM2_RC_xxxx, or SBC_xxxx.
 */
SBCStatus SBC_NvWriteChecked(SBC_TPM_CTX *ctx,
                             const SBC_NV_SLOT *slot,
                             const uint8_t *data,
                             uint16_t size,
                             uint32_t expected_crc);

/**
 * @brief Read NV data and print colored hexdump to stdout.
 *
 * @return SBC_OK, TPM2_RC_xxxx, or SBC_xxxx.
 */
SBCStatus SBC_NvReadHexdump(SBC_TPM_CTX *ctx,
                            const SBC_NV_SLOT *slot);

/**
 * @brief Optional test entry for NV manager.
 *
 * Can be called from your main() or unit tests.
 */
int sbc_nv_test_main(void);

#endif /* SBC_TPM_NV_H */

