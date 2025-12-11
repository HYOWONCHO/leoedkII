/** @file
  @brief
  SBC TPM2 Utility - Vendor Aware Full Implementation (IFX/SLB supported)
**/

#include <Uefi.h>
#include <Library/UefiLib.h>
#include <Library/BaseLib.h>
#include <Library/BaseMemoryLib.h>
#include <Library/DebugLib.h>
#include <IndustryStandard/Tpm20.h>
#include <Library/Tpm2CommandLib.h>
#include <Library/Tpm2DeviceLib.h>

#include "SBC_Log.h"
#include "SBC_Tpm.h"

#define SBC_MAX_TPM_PROPERTIES 64

#ifndef TPM_PT_FIXED
#define TPM_PT_FIXED 0x00000100
#endif

#define SBC_MODEL_UNKNOWN "UNKNOWN"
#pragma pack(push, 1)
// Vendor-info structure
typedef struct {
    BOOLEAN IsStandard;
    BOOLEAN IsInfineon;

    CHAR8 Manufacturer[8];
    CHAR8 Model[16];

    CHAR8 AsciiFW[8];      // e.g., "2.0.3"
    UINT32 FwMajor;
    UINT32 FwMinor;

} SBC_TPM_VENDOR_INFO;


// Capability buffer
typedef struct {
    TPM_CAP Capability;
    struct {
        UINT32 Count;
        TPMS_TAGGED_PROPERTY Property[SBC_MAX_TPM_PROPERTIES];
    } Data;
} SBC_TPM_CAP_DATA;

typedef struct {
    TPM_ST   Tag;
    UINT32   ParamSize;
    TPM_CC   CommandCode;
    UINT16   BytesRequested;
} TPM2_GET_RANDOM_CMD;

typedef struct {
    TPM_ST   Tag;
    UINT32   ParamSize;
    TPM_RC   ResponseCode;
    UINT16   BytesSize;
    UINT8    Data[1];   // flexible array
} TPM2_GET_RANDOM_RSP;
#pragma pack(pop)

STATIC
VOID
SBC_ResetVendorInfo (
    OUT SBC_TPM_VENDOR_INFO *Info
    )
{
    ZeroMem(Info, sizeof(*Info));
    AsciiStrCpyS(Info->Manufacturer, sizeof(Info->Manufacturer), SBC_MODEL_UNKNOWN);
    AsciiStrCpyS(Info->Model, sizeof(Info->Model), SBC_MODEL_UNKNOWN);
    AsciiStrCpyS(Info->AsciiFW, sizeof(Info->AsciiFW), "0.0");
}


/**
  TPM Init
**/
EFI_STATUS
SBC_TpmInit (VOID)
{
    EFI_STATUS Status = Tpm2Startup(TPM_SU_CLEAR);

    if (Status == TPM_RC_INITIALIZE)
        Status = EFI_SUCCESS;

    if (EFI_ERROR(Status)) {
        DEBUG((DEBUG_ERROR, "[TPM] Startup failed (%r)\n", Status));
        return Status;
    }

    Status = Tpm2SelfTest(NO);
    if (EFI_ERROR(Status)) {
        DEBUG((DEBUG_ERROR, "[TPM] SelfTest failed (%r)\n", Status));
        return Status;
    }

    DEBUG((DEBUG_INFO, "[TPM] Init OK\n"));
    return EFI_SUCCESS;
}


EFI_STATUS
SBC_TpmDeinit (VOID)
{
    return Tpm2Shutdown(TPM_SU_CLEAR);
}


/**
  Read a TPM_PT property safely
**/
EFI_STATUS
SBC_GetTpmProperty (
    IN  TPM_PT   Property,
    OUT UINT32  *Value
    )
{
    EFI_STATUS Status;
    TPMI_YES_NO MoreData;
    SBC_TPM_CAP_DATA CapBuf;

    ZeroMem(&CapBuf, sizeof(CapBuf));

    Status = Tpm2GetCapability(
                 TPM_CAP_TPM_PROPERTIES,
                 Property,
                 SBC_MAX_TPM_PROPERTIES,
                 &MoreData,
                 (TPMS_CAPABILITY_DATA *)&CapBuf
             );
    if (EFI_ERROR(Status))
        return Status;

    UINT32 Count = CapBuf.Data.Count;
    if (Count > SBC_MAX_TPM_PROPERTIES)
        Count = SBC_MAX_TPM_PROPERTIES;

    for (UINT32 i = 0; i < Count; i++) {
        if (CapBuf.Data.Property[i].property == Property) {
            *Value = CapBuf.Data.Property[i].value;
            return EFI_SUCCESS;
        }
    }

    return EFI_NOT_FOUND;
}


/**
  Dump TPM Fixed Properties
**/
EFI_STATUS
SBC_DumpTpmFixedProperties (VOID)
{
    EFI_STATUS Status;
    TPMI_YES_NO MoreData;
    SBC_TPM_CAP_DATA CapBuf;

    ZeroMem(&CapBuf, sizeof(CapBuf));

    Status = Tpm2GetCapability(
                 TPM_CAP_TPM_PROPERTIES,
                 TPM_PT_FIXED,
                 SBC_MAX_TPM_PROPERTIES,
                 &MoreData,
                 (TPMS_CAPABILITY_DATA *)&CapBuf
             );

    if (EFI_ERROR(Status)) {
        DEBUG((DEBUG_ERROR, "[TPM] DumpProps failed (%r)\n", Status));
        return Status;
    }

    UINT32 Count = CapBuf.Data.Count;
    if (Count > SBC_MAX_TPM_PROPERTIES)
        Count = SBC_MAX_TPM_PROPERTIES;

    DEBUG((DEBUG_INFO, "===== TPM Fixed Properties (%u entries) =====\n", Count));

    for (UINT32 i = 0; i < Count; i++) {
        DEBUG((DEBUG_INFO, "  PT 0x%08x = 0x%08x\n",
               CapBuf.Data.Property[i].property,
               CapBuf.Data.Property[i].value));
    }

    DEBUG((DEBUG_INFO, "=============================================\n"));
    return EFI_SUCCESS;
}


/**
  Detect Infineon / SLB Vendor patterns
  (Endian-corrected ASCII extraction)
**/
STATIC
VOID
SBC_DetectVendor (
    OUT SBC_TPM_VENDOR_INFO *Info
    )
{
    EFI_STATUS Status;
    TPMI_YES_NO MoreData;
    SBC_TPM_CAP_DATA CapBuf;

    SBC_ResetVendorInfo(Info);
    ZeroMem(&CapBuf, sizeof(CapBuf));

    Status = Tpm2GetCapability(
                 TPM_CAP_TPM_PROPERTIES,
                 TPM_PT_FIXED,
                 SBC_MAX_TPM_PROPERTIES,
                 &MoreData,
                 (TPMS_CAPABILITY_DATA *)&CapBuf
             );

    if (EFI_ERROR(Status))
        return;

    UINT32 Count = CapBuf.Data.Count;
    if (Count > SBC_MAX_TPM_PROPERTIES)
        Count = SBC_MAX_TPM_PROPERTIES;

    for (UINT32 i = 0; i < Count; i++) {

        UINT32 Pt  = CapBuf.Data.Property[i].property;
        UINT32 Val = CapBuf.Data.Property[i].value;

        //
        // Extract ASCII (Little Endian Correct)
        //
        CHAR8 A[5];
        A[0] = (CHAR8)( Val        & 0xFF );
        A[1] = (CHAR8)((Val >>  8) & 0xFF );
        A[2] = (CHAR8)((Val >> 16) & 0xFF );
        A[3] = (CHAR8)((Val >> 24) & 0xFF );
        A[4] = '\0';

        //
        // Vendor: IFX (Infineon)
        //
        if (AsciiStrnCmp(A, "IFX", 3) == 0) {
            Info->IsInfineon = TRUE;
            AsciiStrCpyS(Info->Manufacturer, sizeof(Info->Manufacturer), "IFX");
        }

        //
        // Model: SLB9, SLB6, etc.
        //
        if (AsciiStrnCmp(A, "SLB", 3) == 0) {
            Info->IsInfineon = TRUE;
            AsciiStrCpyS(Info->Model, sizeof(Info->Model), A);
        }

        //
        // Firmware Version: PT 0x00010000 (Vendor-specific ASCII)
        // Example: 0x00302E32 → "2.0.3"
        //
        if (Pt == 0x00010000) {
            CHAR8 FW[5];
            FW[0] = (CHAR8)( Val        & 0xFF );
            FW[1] = (CHAR8)((Val >>  8) & 0xFF );
            FW[2] = (CHAR8)((Val >> 16) & 0xFF );
            FW[3] = (CHAR8)((Val >> 24) & 0xFF );
            FW[4] = '\0';

            AsciiStrCpyS(Info->AsciiFW, sizeof(Info->AsciiFW), FW);
        }
    }

    Info->IsStandard = !Info->IsInfineon;
}


/**
  Print TPM info
**/
EFI_STATUS
SBC_PrintTpmVersionInfo (VOID)
{
    EFI_STATUS Status;
    SBC_TPM_VENDOR_INFO Info;
    UINT32 StdMfg = 0;

    SBC_DetectVendor(&Info);

    DEBUG((DEBUG_INFO, "===== TPM Version / Vendor Information =====\n"));

    //
    // Attempt Standard Manufacturer (TPM_PT_MANUFACTURER)
    //
    Status = SBC_GetTpmProperty(TPM_PT_MANUFACTURER, &StdMfg);
    if (!EFI_ERROR(Status)) {
        CHAR8 Mfg[5];
        Mfg[0] = (StdMfg >> 24) & 0xFF;
        Mfg[1] = (StdMfg >> 16) & 0xFF;
        Mfg[2] = (StdMfg >>  8) & 0xFF;
        Mfg[3] = (StdMfg      ) & 0xFF;
        Mfg[4] = '\0';

        DEBUG((DEBUG_INFO, "Standard Manufacturer : %a\n", Mfg));
    } else {
        DEBUG((DEBUG_INFO, "Standard Manufacturer : (not reported)\n"));
    }

    //
    // Vendor-specific detection
    //
    if (Info.IsInfineon) {
        DEBUG((DEBUG_INFO, "Vendor Detected       : Infineon (IFX)\n"));
        DEBUG((DEBUG_INFO, "Model                 : %a\n", Info.Model));
        DEBUG((DEBUG_INFO, "FW (ASCII Vendor FW)  : %a\n", Info.AsciiFW));
    } else {
        DEBUG((DEBUG_INFO, "Vendor Detected       : Standard / Unknown\n"));
    }

    DEBUG((DEBUG_INFO, "============================================\n"));
    return EFI_SUCCESS;
}


STATIC
EFI_STATUS
SBC_TpmGetRandomOnce (
    IN  UINT16  RequestBytes,
    OUT UINT8  *OutBuffer,
    OUT UINT16 *OutLen
    )
{
    //
    // Command/response structures must be byte-packed.
    //


    EFI_STATUS            Status;
    TPM2_GET_RANDOM_CMD   Cmd;
    UINT8                 RspBuf[sizeof (TPM2_GET_RANDOM_RSP) + 64]; // up to 64 bytes
    UINT32                RspSize;
    TPM2_GET_RANDOM_RSP  *Rsp;
    UINT16                RandomSize;

    if (OutBuffer == NULL || OutLen == NULL) {
        return EFI_INVALID_PARAMETER;
    }

    if (RequestBytes == 0) {
        *OutLen = 0;
        return EFI_SUCCESS;
    }

    //
    // Build command header (TPM wire format is big-endian → use SwapBytesXX)
    //
    Cmd.Tag           = SwapBytes16 (TPM_ST_NO_SESSIONS);
    Cmd.ParamSize     = SwapBytes32 (sizeof (Cmd));
    Cmd.CommandCode   = SwapBytes32 (TPM_CC_GetRandom);
    Cmd.BytesRequested= SwapBytes16 (RequestBytes);

    RspSize = sizeof (RspBuf);
    Status  = Tpm2SubmitCommand (
                  sizeof (Cmd),
                  (UINT8 *)&Cmd,
                  &RspSize,
                  RspBuf
              );

    if (EFI_ERROR (Status)) {
        return EFI_DEVICE_ERROR;
    }

    if (RspSize < sizeof (TPM2_GET_RANDOM_RSP)) {
        return EFI_DEVICE_ERROR;
    }

    Rsp = (TPM2_GET_RANDOM_RSP *)RspBuf;

    //
    // Check response code
    //
    if (SwapBytes32 (Rsp->ResponseCode) != TPM_RC_SUCCESS) {
        return EFI_DEVICE_ERROR;
    }

    RandomSize = SwapBytes16 (Rsp->BytesSize);
    if (RandomSize > RequestBytes) {
        // Should not happen, but clamp just in case
        RandomSize = RequestBytes;
    }

    //
    // Ensure buffer is large enough
    //
    if (sizeof (TPM2_GET_RANDOM_RSP) + RandomSize - 1 > RspSize) {
        return EFI_DEVICE_ERROR;
    }

    CopyMem (OutBuffer, Rsp->Data, RandomSize);
    *OutLen = RandomSize;

    return EFI_SUCCESS;
}


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
    )
{
    EFI_STATUS Status;
    UINT16     Chunk;
    UINT16     Got;

    if (Buffer == NULL || Length == 0) {
        return EFI_INVALID_PARAMETER;
    }

    while (Length > 0) {
        //
        // Request at most 64 bytes per call (보수적으로 제한)
        //
        Chunk = (Length > 64) ? 64 : (UINT16)Length;

        Status = SBC_TpmGetRandomOnce (Chunk, Buffer, &Got);
        if (EFI_ERROR (Status) || Got == 0) {
            DEBUG ((DEBUG_ERROR, "[TPM] GetRandom failed (Status=%r Got=%u)\n", Status, Got));
            return EFI_DEVICE_ERROR;
        }

        Buffer += Got;
        Length -= Got;
    }

    return EFI_SUCCESS;
}
