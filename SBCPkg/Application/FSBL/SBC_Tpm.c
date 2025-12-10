/** @file
  @brief
  SBC TPM2 Utility Library Implementation.
**/
#include <Uefi.h>
#include <Library/UefiLib.h>
#include <Library/DebugLib.h>
#include <Library/BaseLib.h>
#include <Library/Tpm2CommandLib.h>
#include <IndustryStandard/Tpm20.h>

#include "SBC_Log.h"

/**
  @brief
  Initialize TPM2.

  TPM2 requires Startup and SelfTest before capability values become valid.
**/
EFI_STATUS
SBC_TpmInit (
    VOID
    )
{
    EFI_STATUS Status;

    //
    // TPM Startup
    //
    Status = Tpm2Startup (TPM_SU_CLEAR);

    if (Status == TPM_RC_INITIALIZE) {
        //
        // TPM already initialized → treat as success.
        //

        sbc_err_sysprn(SBC_LOG_CMN_PRIO_INFO, 2,
                     SYS_LOG_HOST_BOOT,
                     SYS_LOG_APP_NAME,
                     SYS_LOG_CSC_NAME,
                     0,
                     L"Detetion",
                     L"SBC_VENDOR_SP Already  the TPM Initialize  \n");
        Status = EFI_SUCCESS;
    } else if (EFI_ERROR (Status)) {
        sbc_err_sysprn(SBC_LOG_CMN_PRIO_ERR, 2,
                     SYS_LOG_HOST_BOOT,
                     SYS_LOG_APP_NAME,
                     SYS_LOG_CSC_NAME,
                     0,
                     L"Detetion",
                     L"SBC_VENDOR_SP Failed to TPM Startup \n");
        DEBUG ((DEBUG_ERROR, "[TPM] Startup failed (%r)\n", Status));
        return Status;
    }

    sbc_err_sysprn(SBC_LOG_CMN_PRIO_INFO, 2,
                     SYS_LOG_HOST_BOOT,
                     SYS_LOG_APP_NAME,
                     SYS_LOG_CSC_NAME,
                     0,
                     L"Detetion",
                     L"SBC_VENDOR_SP Successs to  the TPM Initialize  \n");

    //
    // TPM SelfTest
    //
    Status = Tpm2SelfTest (NO);
    if (EFI_ERROR (Status)) {
        sbc_err_sysprn(SBC_LOG_CMN_PRIO_ERR, 2,
                     SYS_LOG_HOST_BOOT,
                     SYS_LOG_APP_NAME,
                     SYS_LOG_CSC_NAME,
                     0,
                     L"Detetion",
                     L"SBC_VENDOR_SP Failed to TPM2 Self-test \n");
        DEBUG ((DEBUG_ERROR, "[TPM] SelfTest failed (%r)\n", Status));
        return Status;
    }

    sbc_err_sysprn(SBC_LOG_CMN_PRIO_ERR, 2,
                     SYS_LOG_HOST_BOOT,
                     SYS_LOG_APP_NAME,
                     SYS_LOG_CSC_NAME,
                     0,
                     L"Detetion",
                     L"SBC_VENDOR_SP Successed to TPM2 Self-test \n");
    DEBUG ((DEBUG_INFO, "[TPM] Init OK\n"));
    return EFI_SUCCESS;
}

/**
  @brief
  Deinitialize TPM2 using TPM2_Shutdown().
**/
EFI_STATUS
SBC_TpmDeinit (
    VOID
    )
{
    EFI_STATUS Status;

    Status = Tpm2Shutdown (TPM_SU_CLEAR);
    if (EFI_ERROR (Status)) {
        DEBUG ((DEBUG_ERROR, "[TPM] Shutdown failed (%r)\n", Status));
        return Status;
    }

    DEBUG ((DEBUG_INFO, "[TPM] Deinit OK\n"));
    return EFI_SUCCESS;
}

/**
  @brief Retrieve a TPM_PT property safely.
**/
EFI_STATUS
SBC_GetTpmProperty (
    IN  TPM_PT    Property,
    OUT UINT32   *Value
    )
{
    EFI_STATUS           Status;
    TPMI_YES_NO          MoreData;
    TPMS_CAPABILITY_DATA CapData;
    UINT32               Count;
    UINT32               i;

    Status = Tpm2GetCapability (
                 TPM_CAP_TPM_PROPERTIES,
                 Property,
                 1,
                 &MoreData,
                 &CapData       // ← 구조체 주소 전달
             );

    if (EFI_ERROR (Status)) {
        DEBUG ((DEBUG_ERROR, "[TPM] GetCapability failed (%r)\n", Status));
        return Status;
    }

    Count = CapData.data.tpmProperties.count;

    for (i = 0; i < Count; i++) {
        if (CapData.data.tpmProperties.tpmProperty[i].property == Property) {
            *Value = CapData.data.tpmProperties.tpmProperty[i].value;
            return EFI_SUCCESS;
        }
    }

    DEBUG ((DEBUG_WARN, "[TPM] Property 0x%x not found\n", Property));
    return EFI_NOT_FOUND;
}


/**
  @brief Retrieve TPM Firmware Version.
**/
EFI_STATUS
SBC_GetFirmwareVersion (
    OUT UINT32 *Fw1,
    OUT UINT32 *Fw2
    )
{
    EFI_STATUS Status;

    Status = SBC_GetTpmProperty (TPM_PT_FIRMWARE_VERSION_1, Fw1);
    if (EFI_ERROR (Status)) {
        return Status;
    }

    Status = SBC_GetTpmProperty (TPM_PT_FIRMWARE_VERSION_2, Fw2);
    if (EFI_ERROR (Status)) {
        return Status;
    }

    return EFI_SUCCESS;
}

/**
  @brief Retrieve TPM Manufacturer ID.
**/
EFI_STATUS
SBC_GetManufacturerID (
    OUT UINT32 *MfgId
    )
{
    return SBC_GetTpmProperty (TPM_PT_MANUFACTURER, MfgId);
}

/**
  @brief Print TPM Version information.
**/
EFI_STATUS
SBC_PrintTpmVersionInfo (
    VOID
    )
{
    EFI_STATUS Status;
    UINT32     Fw1, Fw2;
    UINT32     Mfg;
    CHAR8      Vendor[5];

    DEBUG ((DEBUG_INFO, "===== TPM Version Information =====\n"));

    //
    // Firmware version
    //
    Status = SBC_GetFirmwareVersion (&Fw1, &Fw2);
    if (EFI_ERROR (Status)) {
        DEBUG ((DEBUG_ERROR, "[TPM] Firmware version read failed (%r)\n", Status));
        return Status;
    }

    DEBUG ((DEBUG_INFO, "Firmware Version : %u.%u\n", Fw1, Fw2));

    //
    // Manufacturer ID
    //
    Status = SBC_GetManufacturerID (&Mfg);
    if (EFI_ERROR (Status)) {
        DEBUG ((DEBUG_ERROR, "[TPM] Manufacturer read failed (%r)\n", Status));
        return Status;
    }

    Vendor[0] = (Mfg >> 24) & 0xFF;
    Vendor[1] = (Mfg >> 16) & 0xFF;
    Vendor[2] = (Mfg >>  8) & 0xFF;
    Vendor[3] = (Mfg      ) & 0xFF;
    Vendor[4] = '\0';

    DEBUG ((DEBUG_INFO, "Manufacturer     : %a\n", Vendor));
    DEBUG ((DEBUG_INFO, "===================================\n"));

    return EFI_SUCCESS;
}

