#include "sbc_tpm_version.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>


int tpm_print_random(void)
{
    ESYS_CONTEXT *esys = NULL;
    TSS2_TCTI_CONTEXT *tcti_ctx = NULL;
    TSS2_RC rc;

    // -------------------------------------------------------
    // Initialize TCTI (device)
    // -------------------------------------------------------
    rc = Tss2_Tcti_Device_Init(NULL, 0, TPM_DEVICE);
    if (rc != TSS2_RC_SUCCESS) {
        printf("TCTI size query failed\n");
        return -1;
    }

    size_t tcti_size;
    Tss2_Tcti_Device_Init(NULL, &tcti_size, TPM_DEVICE);
    tcti_ctx = (TSS2_TCTI_CONTEXT*)malloc(tcti_size);

    rc = Tss2_Tcti_Device_Init(tcti_ctx, &tcti_size, TPM_DEVICE);
    if (rc != TSS2_RC_SUCCESS) {
        printf("Failed to initialize TCTI\n");
        return -1;
    }

    // -------------------------------------------------------
    // Initialize ESYS
    // -------------------------------------------------------
    rc = Esys_Initialize(&esys, tcti_ctx, NULL);
    if (rc != TSS2_RC_SUCCESS) {
        printf("Esys_Initialize failed\n");
        return -1;
    }

    // -------------------------------------------------------
    // Get random bytes
    // -------------------------------------------------------
    TPM2B_DIGEST *random_bytes;
    rc = Esys_GetRandom(esys, ESYS_TR_NONE, ESYS_TR_NONE, ESYS_TR_NONE,
                        16, &random_bytes);

    if (rc != TSS2_RC_SUCCESS) {
        printf("Esys_GetRandom failed\n");
        return -1;
    }

    printf("TPM Random (16 bytes): ");
    for (int i = 0; i < random_bytes->size; i++)
        printf("%02X ", random_bytes->buffer[i]);
    printf("\n");

    Esys_Free(random_bytes);
    Esys_Finalize(&esys);
    free(tcti_ctx);

    return 0;
}

int tpm_print_version(void)
{
    printf("TPM2 Example Build - Using TPM2-TSS\n");
    return 0;
}

