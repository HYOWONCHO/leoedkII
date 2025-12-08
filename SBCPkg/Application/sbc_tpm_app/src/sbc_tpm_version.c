#include "sbc_tpm_version.h"
#include "sbc_tpm_nv.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>



#include <tss2/tss2_esys.h>
#include <tss2/tss2_tcti_device.h>

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


static ESYS_CONTEXT *init_esys(void)
{
    TSS2_TCTI_CONTEXT *tcti_ctx = NULL;
    ESYS_CONTEXT *esys = NULL;
    TSS2_RC rc;
    size_t tcti_size;

    // Query required size
    Tss2_Tcti_Device_Init(NULL, &tcti_size, TPM_DEVICE);
    tcti_ctx = (TSS2_TCTI_CONTEXT*)malloc(tcti_size);

    rc = Tss2_Tcti_Device_Init(tcti_ctx, &tcti_size, TPM_DEVICE);
    if (rc != TSS2_RC_SUCCESS) {
        printf("TCTI Init failed: 0x%X\n", rc);
        return NULL;
    }

    rc = Esys_Initialize(&esys, tcti_ctx, NULL);
    if (rc != TSS2_RC_SUCCESS) {
        printf("Esys_Initialize failed: 0x%X\n", rc);
        free(tcti_ctx);
        return NULL;
    }
    return esys;
}

int tpm_print_version(void)
{
    ESYS_CONTEXT *esys = init_esys();
    if (!esys) {
        printf("TPM initialization failed\n");
        return -1;
    }

    TSS2_RC rc;
    TPMS_CAPABILITY_DATA *capability = NULL;

    // ------------------------------------------------------------
    // Query TPM2 Version / Properties
    // ------------------------------------------------------------
    rc = Esys_GetCapability(
            esys,
            ESYS_TR_NONE,
            ESYS_TR_NONE,
            ESYS_TR_NONE,
            TPM2_CAP_TPM_PROPERTIES,
            TPM2_PT_MANUFACTURER,   // property start
            20,                     // property count
            NULL,
            &capability);

    if (rc != TSS2_RC_SUCCESS) {
        printf("Esys_GetCapability failed: 0x%X\n", rc);
        return -1;
    }

    printf("\n===== TPM2 Version Information =====\n");

    for (UINT32 i = 0; i < capability->data.tpmProperties.count; i++) {
        TPM2_CAP tag = capability->data.tpmProperties.tpmProperty[i].property;
        UINT32 val = capability->data.tpmProperties.tpmProperty[i].value;

        switch(tag) {

            case TPM2_PT_MANUFACTURER:
                printf("Manufacturer  : %c%c%c%c (0x%X)\n",
                       (val >> 24) & 0xFF,
                       (val >> 16) & 0xFF,
                       (val >> 8) & 0xFF,
                       val & 0xFF,
                       val);
                break;

            case TPM2_PT_VENDOR_STRING_1:
            case TPM2_PT_VENDOR_STRING_2:
            case TPM2_PT_VENDOR_STRING_3:
            case TPM2_PT_VENDOR_STRING_4:
            {
                char s[5] = {0};
                s[0] = (val >> 24) & 0xFF;
                s[1] = (val >> 16) & 0xFF;
                s[2] = (val >> 8) & 0xFF;
                s[3] = val & 0xFF;
                printf("Vendor String : %s\n", s);
            }
            break;

            case TPM2_PT_FIRMWARE_VERSION_1:
                printf("FW Version 1  : %u.%u\n",
                       (val >> 16) & 0xFFFF,
                       val & 0xFFFF);
                break;

            case TPM2_PT_FIRMWARE_VERSION_2:
                printf("FW Version 2  : %u.%u\n",
                       (val >> 16) & 0xFFFF,
                       val & 0xFFFF);
                break;

            case TPM2_PT_REVISION:
                printf("TPM Revision  : %u\n", val);
                break;

            default:
                break;
        }
    }

    printf("====================================\n\n");

    Esys_Free(capability);
    Esys_Finalize(&esys);
    return 0;
}



