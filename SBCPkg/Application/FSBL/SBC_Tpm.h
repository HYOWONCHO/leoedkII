/** @file
  @brief
  SBC TPM2 Utility Library Header.

  This module provides TPM2 initialization, deinitialization,
  property access, firmware version retrieval, and manufacturer ID
  utilities for use in DXE applications or drivers.

  @note
  Requires Tpm2CommandLib and Tpm2DeviceLib to be declared in INF.

**/

#ifndef __SBC_TPM_H__
#define __SBC_TPM_H__

#include <Library/Tpm2CommandLib.h>
#include <IndustryStandard/Tpm20.h>

//
// Public APIs
//

/**
  @brief Initialize TPM2 (Startup + SelfTest)

  @retval EFI_SUCCESS   TPM initialization succeeded or already initialized.
  @retval Others        TPM commands failed.
**/
EFI_STATUS
SBC_TpmInit (
    VOID
    );

/**
  @brief Deinitialize TPM2.

  Performs TPM2_Shutdown() in CLEAR mode.

  @retval EFI_SUCCESS   TPM shutdown succeeded.
  @retval Others        TPM command failed.
**/
EFI_STATUS
SBC_TpmDeinit (
    VOID
    );

/**
  @brief Retrieve a specific TPM2 capability property.

  @param[in]  Property   TPM_PT_xxx property.
  @param[out] Value      Returned value.

  @retval EFI_SUCCESS     Property found.
  @retval EFI_NOT_FOUND   Property not returned.
  @retval Others          Command failed.
**/
EFI_STATUS
SBC_GetTpmProperty (
    IN  TPM_PT    Property,
    OUT UINT32   *Value
    );

/**
  @brief Retrieve TPM firmware version information.

  Firmware version = Fw1.Fw2

  @retval EFI_SUCCESS   Version retrieved.
  @retval Others        Command failed.
**/
EFI_STATUS
SBC_GetFirmwareVersion (
    OUT UINT32 *Fw1,
    OUT UINT32 *Fw2
    );

/**
  @brief Retrieve TPM manufacturer ID (ASCII 4 chars encoded in UINT32).

  @retval EFI_SUCCESS   ID retrieved.
  @retval Others        Command failed.
**/
EFI_STATUS
SBC_GetManufacturerID (
    OUT UINT32 *MfgId
    );

/**
  @brief Print all TPM version information (firmware + manufacturer).

  @retval EFI_SUCCESS   Printed successfully.
**/
EFI_STATUS
SBC_PrintTpmVersionInfo (
    VOID
    );

#endif // __SBC_TPM_H__

