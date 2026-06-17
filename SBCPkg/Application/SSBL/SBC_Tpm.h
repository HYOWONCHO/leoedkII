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


/* VT100 colors (change as you like) */
#ifndef C_RST
    #define C_RST   "\033[0m"
#endif
#ifndef C_DIM
    #define C_DIM   "\033[2m"
#endif
#ifndef C_HEX
    #define C_HEX   "\033[36m"  /* cyan */
#endif
#ifndef C_ASC
    #define C_ASC   "\033[33m"  /* yellow */
#endif
#ifndef C_OFF
    #define C_OFF   "\033[90m"  /* bright black */
#endif
#ifndef C_GRN
    #define C_GRN   "\033[35m"  /* bright black */
#endif
#ifndef C_BLU
    #define C_BLU   "\033[37m"  /* bright black */
#endif



#ifndef SBC_TPMA_NV_AUTHREAD
#define SBC_TPMA_NV_AUTHREAD     (1 << 18)
#endif

#ifndef SBC_TPMA_NV_AUTHWRITE
#define SBC_TPMA_NV_AUTHWRITE    (1 << 19)
#endif

#ifndef SBC_TPMA_NV_OWNERREAD
#define SBC_TPMA_NV_OWNERREAD    (1 << 16)
#endif

#ifndef SBC_TPMA_NV_OWNERWRITE
#define SBC_TPMA_NV_OWNERWRITE   (1 << 17)
#endif

#define NV_KEY_DEVICE_ID            0x01500001   /* 32 bytes */
#define NV_KEY_FIRMWARE_ID          0x01500002
#define NV_KEY_OS_ID                0x01500003
#define NV_KEY_BASEANSWER_ID        0x01500003


#define NV_ROOT_CA_ID               0x01500101   /* 512 bytes */
#define NV_DEVICE_CA_ID             0x01500102
#define NV_FIRMWARE_CA_ID           0x01500103
#define NV_OS_CA_ID                 0x01500104

#define NV_KEY_SIZE     64 
#define NV_CERT_SIZE    768

/**
  NV slot descriptor (UEFI side).

 *name  : logical name (ASCII) 
 * index : NV index handle (0x01XXXXXX range) size  : expected
 * data sizes
**/
typedef struct {
  TPMI_RH_NV_INDEX Index;
  UINT16           Size;
  CONST CHAR8     *Name;
} SBC_NV_SLOT;
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


EFI_STATUS
SBC_DumpTpmFixedProperties (
    VOID
    );


/**
  @brief
  Generate random bytes using TPM2_GetRandom.

  @param[out] Buffer   Output buffer for random bytes
  @param[in]  Length   Number of random bytes to generate

  @retval EFI_SUCCESS          Success
  @retval EFI_INVALID_PARAMETER Buffer is NULL or Length == 0
  @retval EFI_DEVICE_ERROR     TPM returned an error
**/
EFI_STATUS
SBC_TpmGetRandom (
    OUT UINT8  *Buffer,
    IN  UINT32  Length
    );

EFI_STATUS
SBC_NvReadBuffer (
  IN  CONST SBC_NV_SLOT *Slot,
  OUT UINT8             *OutBuf,
  IN  UINT16             OutBufSize,
  OUT UINT16            *OutReadSize OPTIONAL
  );

SBC_NV_SLOT *
SBC_NvFindSlotByName (
  IN CONST CHAR8 *Name
  );

/**
  @brief Write data into NV after CRC check.

  @param[in] Slot         NV slot descriptor.
  @param[in] Data         Data to write.
  @param[in] Size         Data size (must match Slot->Size).
  @param[in] ExpectedCrc  If non-zero, compare with computed CRC and fail on mismatch.

  @retval EFI_SUCCESS         Write OK.
  @retval EFI_INVALID_PARAMETER  Slot/Data invalid, or size mismatch.
  @retval EFI_COMPROMISED_DATA   CRC mismatch.
  @retval Others                 Error from NV operations.
**/
EFI_STATUS
SBC_NvWriteChecked (
  IN CONST SBC_NV_SLOT *Slot,
  IN CONST UINT8       *Data,
  IN UINT16             Size,
  IN UINT32             ExpectedCrc
  );
#endif // __SBC_TPM_H__
