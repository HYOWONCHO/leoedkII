#include <stdio.h>
#include <string.h>
#include <stdint.h>
#include <stdlib.h>
#include <fcntl.h>
#include <unistd.h>

#include "sbc_tpm_version.h"
#include "sbc_tpm_nv.h"


/**
 * @brief Generate cryptographically secure random bytes.
 * Use /dev/urandom when available.
 */
static void sbc_generate_random(uint8_t *buf, size_t size)
{
    int fd = open("/dev/urandom", O_RDONLY);
    if (fd >= 0) {
        read(fd, buf, size);
        close(fd);
        return;
    }

    /* Fallback: insecure PRNG, but workable if urandom unavailable */
    for (size_t i = 0; i < size; i++)
        buf[i] = (uint8_t)(rand() & 0xFF);
}


int main(int argc, char *argv[])
{
    extern int sbc_nv_tetst_main(void);


    tpm_print_version();
    sbc_nv_test_main();

#if 0

    SBC_TPM_CTX ctx;
    SBCStatus st;

    printf("\n=== SBC TPM NV Example (Random KEY1 / CERT1) ===\n\n");

    /* --------------------------------------------------------
     * 1) Prepare random KEY1 (32 bytes) and CERT1 (512 bytes)
     * -------------------------------------------------------- */
    uint8_t random_key1[32];
    uint8_t random_cert1[512];  


    sbc_generate_random(random_key1, sizeof(random_key1));
    sbc_generate_random(random_cert1, sizeof(random_cert1));

    printf("Generated random KEY1 (32 bytes)\n");
    hexdump_color(random_key1, sizeof(random_key1));

    printf("\nGenerated random CERT1 (512 bytes, first 64 bytes shown)\n");
    hexdump_color(random_cert1, 64);

    /* --------------------------------------------------------
     * 2) Initialize TPM (device:/dev/tpm0)
     * -------------------------------------------------------- */
    st = SBC_TpmInit(&ctx, "device:/dev/tpm0");
    if (st != SBC_OK) {
        printf("TPM init failed: %d\n", st);
        return 1;
    }

    /* Get NV slot from table */
    const SBC_NV_SLOT *slot_key1  = SBC_NvFindSlotByName("KEY1");
    const SBC_NV_SLOT *slot_cert1 = SBC_NvFindSlotByName("CERT1");

    if (!slot_key1 || !slot_cert1) {
        printf("ERROR: NV table missing KEY1 or CERT1\n");
        SBC_TpmFinish(&ctx);
        return 1;
    }

    /* --------------------------------------------------------
     * 3) Write KEY1
     * -------------------------------------------------------- */
    printf("\n>>> Writing KEY1 (random 32-byte)\n");

    st = SBC_NvWriteChecked(&ctx,
                            slot_key1,
                            random_key1,
                            sizeof(random_key1),
                            0);
    if (st != SBC_OK) {
        printf("Write KEY1 failed: %d\n", st);
        SBC_TpmFinish(&ctx);
        return 1;
    }

    /* Read KEY1 */
    printf("\n>>> Reading KEY1\n");
    SBC_NvReadHexdump(&ctx, slot_key1);

    /* --------------------------------------------------------
     * 4) Write CERT1 (random 512-byte)
     * -------------------------------------------------------- */
    printf("\n>>> Writing CERT1 (random 512-byte)\n");

    st = SBC_NvWriteChecked(&ctx,
                            slot_cert1,
                            random_cert1,
                            sizeof(random_cert1),
                            0);
    if (st != SBC_OK) {
        printf("Write CERT1 failed: %d\n", st);
        SBC_TpmFinish(&ctx);
        return 1;
    }

    /* Read CERT1 */
    printf("\n>>> Reading CERT1 (full)\n");
    SBC_NvReadHexdump(&ctx, slot_cert1);

    /* --------------------------------------------------------
     * 5) Cleanup
     * -------------------------------------------------------- */
    SBC_TpmFinish(&ctx);

    printf("\n=== Example Finished ===\n\n");
#endif

    return 0;

}
