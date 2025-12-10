/** @file
  @brief
  SBC TPM2 Utility Library Implementation.

  This module provides helper functions to:
    - Initialize and de-initialize TPM2
    - Retrieve basic TPM properties (firmware version, manufacturer ID)
    - Print human readable TPM version information
**/

#include <Uefi.h>
#include <Library/UefiLib.h>
#include <Library/DebugLib.h>
#include <Library/BaseLib.h>
#include <Library/BaseMemoryLib.h>

#include <IndustryStandard/Tpm20.h>
#include <Library/Tpm2CommandLib.h>

#include "SBC_Log.h"
#include "SBC_Tpm.h"

//
// Optional: adjust these if you want stricter logging classification
//
#define SBC_TPM_LOG_TAG_INIT      L"SBC_TPM_INIT"
#define SBC_TPM_LOG_TAG_CAP       L"SBC_TPM_CAP"

//
// Internal helper to decode firmware version format:
// Many TPMs encode firmware version as:
//   - Major : upper 16 bits
//   - Minor : lower 16 bits
//
STATIC
VOID
SBC_DecodeFirmwareVersion (
  IN  UINT32  Raw,
  OUT UINT16 *Major,
  OUT UINT16 *Minor
  )
{
  if (Major != NULL) {
    *Major = (UINT16)(Raw >> 16);
  }

  if (Minor != NULL) {
    *Minor = (UINT16)(Raw & 0xFFFF);
  }
}

/**
  @brief
  Initialize TPM2.

  This function performs the minimal TPM2 initialization sequence required
  before querying capability values:

    1. TPM2_Startup (TPM_SU_CLEAR)
    2. TPM2_SelfTest (NO)

  Some platforms may already have executed TPM2_Startup in an earlier boot
  phase. In such a case the TPM can respond with TPM_RC_INITIALIZE which
  is treated as a successful condition here.
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

  //
  // Many firmware stacks return TPM_RC_INITIALIZE directly if TPM has
  // already been started in a previous phase. Treat this as success.
  //
  if (Status == TPM_RC_INITIALIZE) {
    sbc_err_sysprn (
      SBC_LOG_CMN_PRIO_INFO,
      2,
      SYS_LOG_HOST_BOOT,
      SYS_LOG_APP_NAME,
      SYS_LOG_CSC_NAME,
      0,
      L"Detection",
      L"SBC_TPM: TPM already initialized. Treat as success.\n"
      );

    Status = EFI_SUCCESS;
  } else if (EFI_ERROR (Status)) {
    sbc_err_sysprn (
      SBC_LOG_CMN_PRIO_ERR,
      2,
      SYS_LOG_HOST_BOOT,
      SYS_LOG_APP_NAME,
      SYS_LOG_CSC_NAME,
      0,
      L"Detection",
      L"SBC_TPM: TPM Startup failed.\n"
      );
    DEBUG ((DEBUG_ERROR, "[TPM] Startup failed (%r)\n", Status));
    return Status;
  }

  sbc_err_sysprn (
    SBC_LOG_CMN_PRIO_INFO,
    2,
    SYS_LOG_HOST_BOOT,
    SYS_LOG_APP_NAME,
    SYS_LOG_CSC_NAME,
    0,
    L"Detection",
    L"SBC_TPM: TPM Startup / Initialize success.\n"
    );

  //
  // TPM SelfTest
  //
  Status = Tpm2SelfTest (NO);
  if (EFI_ERROR (Status)) {
    sbc_err_sysprn (
      SBC_LOG_CMN_PRIO_ERR,
      2,
      SYS_LOG_HOST_BOOT,
      SYS_LOG_APP_NAME,
      SYS_LOG_CSC_NAME,
      0,
      L"Detection",
      L"SBC_TPM: TPM2 Self-Test failed.\n"
      );
    DEBUG ((DEBUG_ERROR, "[TPM] SelfTest failed (%r)\n", Status));
    return Status;
  }

  sbc_err_sysprn (
    SBC_LOG_CMN_PRIO_INFO,
    2,
    SYS_LOG_HOST_BOOT,
    SYS_LOG_APP_NAME,
    SYS_LOG_CSC_NAME,
    0,
    L"Detection",
    L"SBC_TPM: TPM2 Self-Test success.\n"
    );

  DEBUG ((DEBUG_INFO, "[TPM] Init OK\n"));

  //
  // Optional: overall “Init OK” log
  //
  sbc_err_sysprn (
    SBC_LOG_CMN_PRIO_INFO,
    2,
    SYS_LOG_HOST_BOOT,
    SYS_LOG_APP_NAME,
    SYS_LOG_CSC_NAME,
    0,
    L"Detection",
    L"SBC_TPM: TPM Init OK.\n"
    );

  return EFI_SUCCESS;
}

/**
  @brief
  Deinitialize TPM2 using TPM2_Shutdown().

  TPM is shut down with TPM_SU_CLEAR which resets volatile state.
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
    sbc_err_sysprn (
      SBC_LOG_CMN_PRIO_ERR,
      2,
      SYS_LOG_HOST_BOOT,
      SYS_LOG_APP_NAME,
      SYS_LOG_CSC_NAME,
      0,
      L"Detection",
      L"SBC_TPM: TPM Shutdown failed.\n"
      );
    return Status;
  }

  DEBUG ((DEBUG_INFO, "[TPM] Deinit OK\n"));
  sbc_err_sysprn (
    SBC_LOG_CMN_PRIO_INFO,
    2,
    SYS_LOG_HOST_BOOT,
    SYS_LOG_APP_NAME,
    SYS_LOG_CSC_NAME,
    0,
    L"Detection",
    L"SBC_TPM: TPM Deinit OK.\n"
    );

  return EFI_SUCCESS;
}

/**
  @brief
  Retrieve a TPM_PT property.

  This function wraps TPM2_GetCapability with TPM_CAP_TPM_PROPERTIES and
  extracts a single 32-bit TPM_PT_* property value.

  @param[in]  Property   TPM_PT_* property selector.
  @param[out] Value      Pointer to a caller-allocated UINT32 that receives
                         the property value.

  @retval EFI_SUCCESS           Property was found and value is returned.
  @retval EFI_INVALID_PARAMETER Value is NULL.
  @retval EFI_NOT_FOUND         Property was not present in the response.
  @retval Others                Error from Tpm2GetCapability().
**/
EFI_STATUS
SBC_GetTpmProperty (
    IN  TPM_PT   Property,
    OUT UINT32  *Value
    )
{
    EFI_STATUS  Status;
    TPMI_YES_NO MoreData;

    //
    // Define maximum number of TPM properties to scan.
    // Adjust this value if you want to read even more.
    //
    #define SBC_MAX_TPM_PROPERTIES 64

    //
    // Create a sufficiently large buffer to prevent overflow.
    //
    typedef struct {
        TPM_CAP Capability;
        struct {
            UINT32 Count;
            TPMS_TAGGED_PROPERTY Property[SBC_MAX_TPM_PROPERTIES];
        } Data;
    } SBC_TPM_CAP_DATA;

    SBC_TPM_CAP_DATA      CapBuf;
    TPMS_CAPABILITY_DATA *CapData = (TPMS_CAPABILITY_DATA *)&CapBuf;

    ZeroMem (&CapBuf, sizeof(CapBuf));

    //
    // Retrieve a wide range of TPM properties starting from the given Property.
    //
    Status = Tpm2GetCapability(
                 TPM_CAP_TPM_PROPERTIES,
                 Property,                 // Starting property code
                 SBC_MAX_TPM_PROPERTIES,   // Maximum number of entries
                 &MoreData,
                 CapData
             );

    if (EFI_ERROR(Status)) {
        return Status;
    }

    UINT32 Count = CapData->data.tpmProperties.count;
    if (Count > SBC_MAX_TPM_PROPERTIES)
        Count = SBC_MAX_TPM_PROPERTIES;

    //
    // Find the requested property in returned list.
    //
    for (UINT32 i = 0; i < Count; i++) {
        if (CapData->data.tpmProperties.tpmProperty[i].property == Property) {
            *Value = CapData->data.tpmProperties.tpmProperty[i].value;
            return EFI_SUCCESS;
        }
    }

    return EFI_NOT_FOUND;
}

/**
  @brief
  Retrieve TPM Firmware Version.

  This function reads both TPM_PT_FIRMWARE_VERSION_1 and
  TPM_PT_FIRMWARE_VERSION_2.

  Raw values are returned as 32-bit integers. Callers may interpret them
  as vendor-specific or split into Major/Minor using helper logic.

  @param[out] Fw1   TPM_PT_FIRMWARE_VERSION_1 value.
  @param[out] Fw2   TPM_PT_FIRMWARE_VERSION_2 value.

  @retval EFI_SUCCESS    Firmware versions retrieved.
  @retval Others         Failed to read from TPM.
**/
EFI_STATUS
SBC_GetFirmwareVersion (
  OUT UINT32 *Fw1,
  OUT UINT32 *Fw2
  )
{
  EFI_STATUS Status;

  if ((Fw1 == NULL) || (Fw2 == NULL)) {
    return EFI_INVALID_PARAMETER;
  }

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
  @brief
  Retrieve TPM Manufacturer ID.

  The manufacturer ID is a 32-bit value, commonly interpreted as a
  4-character ASCII vendor string (for example 'IFX', 'INTC', etc).

  @param[out] MfgId   Manufacturer ID raw value.

  @retval EFI_SUCCESS Manufacturer ID retrieved.
  @retval Others      Failed to read from TPM.
**/
EFI_STATUS
SBC_GetManufacturerID (
  OUT UINT32 *MfgId
  )
{
  if (MfgId == NULL) {
    return EFI_INVALID_PARAMETER;
  }

  return SBC_GetTpmProperty (TPM_PT_MANUFACTURER, MfgId);
}

/**
  @brief
  Print TPM Version information.

  This function prints:
    - Raw firmware version values
    - Decoded Major/Minor if they look reasonable
    - Manufacturer ID as 4-character ASCII string

  All output is done via DEBUG() macros so that it is visible on the
  serial debug console.
**/
EFI_STATUS
SBC_PrintTpmVersionInfo (
  VOID
  )
{
  EFI_STATUS Status;
  UINT32     Fw1Raw;
  UINT32     Fw2Raw;
  UINT16     Fw1Major;
  UINT16     Fw1Minor;
  UINT16     Fw2Major;
  UINT16     Fw2Minor;
  UINT32     Mfg;
  CHAR8      Vendor[5];

  DEBUG ((DEBUG_INFO, "===== TPM Version Information =====\n"));

  //
  // Firmware version
  //
  Status = SBC_GetFirmwareVersion (&Fw1Raw, &Fw2Raw);
  if (EFI_ERROR (Status)) {
    DEBUG ((DEBUG_ERROR, "[TPM] Firmware version read failed (%r)\n", Status));
    return Status;
  }

  SBC_DecodeFirmwareVersion (Fw1Raw, &Fw1Major, &Fw1Minor);
  SBC_DecodeFirmwareVersion (Fw2Raw, &Fw2Major, &Fw2Minor);

  DEBUG ((
    DEBUG_INFO,
    "Firmware Version (raw)   : 0x%08x, 0x%08x\n",
    Fw1Raw,
    Fw2Raw
    ));
  DEBUG ((
    DEBUG_INFO,
    "Firmware Version (dec)   : %u.%u  /  %u.%u\n",
    Fw1Major,
    Fw1Minor,
    Fw2Major,
    Fw2Minor
    ));

  //
  // Manufacturer ID
  //
  Status = SBC_GetManufacturerID (&Mfg);
  if (EFI_ERROR (Status)) {
    DEBUG ((DEBUG_ERROR, "[TPM] Manufacturer read failed (%r)\n", Status));
    return Status;
  }

  Vendor[0] = (CHAR8)((Mfg >> 24) & 0xFF);
  Vendor[1] = (CHAR8)((Mfg >> 16) & 0xFF);
  Vendor[2] = (CHAR8)((Mfg >>  8) & 0xFF);
  Vendor[3] = (CHAR8)( Mfg        & 0xFF);
  Vendor[4] = '\0';

  DEBUG ((DEBUG_INFO, "Manufacturer (raw)       : 0x%08x\n", Mfg));
  DEBUG ((DEBUG_INFO, "Manufacturer (string)    : %a\n", Vendor));
  DEBUG ((DEBUG_INFO, "===================================\n"));

  return EFI_SUCCESS;
}

