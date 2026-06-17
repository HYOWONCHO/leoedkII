/** @file
  @brief
  SBC TPM2 Utility - Vendor Aware Full Implementation (IFX/SLB supported)
**/

#include <Uefi.h>
#include <Library/UefiLib.h>
#include <Library/BaseLib.h>
#include <Library/BaseMemoryLib.h>
#include <Library/MemoryAllocationLib.h>
#include <Library/DebugLib.h>
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



/* External table defined elsewhere (same 개념 as g_nv_table in app) */
SBC_NV_SLOT g_nv_table[] = {
    { NV_KEY_DEVICE_ID,             NV_KEY_SIZE,  "Device ID Key"  },
    { NV_KEY_FIRMWARE_ID,           NV_KEY_SIZE,  "Firmware ID Key"  },
    { NV_KEY_OS_ID,                 NV_KEY_SIZE,  "OS ID Key"  },
    { NV_KEY_BASEANSWER_ID,         NV_KEY_SIZE,  "Baseanswer Key" },
    { NV_ROOT_CA_ID,                NV_CERT_SIZE, "ROOT CA" },
    { NV_DEVICE_CA_ID,              NV_CERT_SIZE, "DeviceID CA" },
    { NV_FIRMWARE_CA_ID,            NV_CERT_SIZE, "FirmwareID CA"},
    { NV_OS_CA_ID,                  NV_CERT_SIZE, "OSID CA" },

};
UINTN       g_nv_table_count;

//
// Standard CRC32 Table (IEEE 802.3)
// Polynomial: 0xEDB88320
//
STATIC CONST UINT32 Crc32Table[256] = {
    0x00000000, 0x77073096, 0xEE0E612C, 0x990951BA,
    0x076DC419, 0x706AF48F, 0xE963A535, 0x9E6495A3,
    0x0EDB8832, 0x79DCB8A4, 0xE0D5E91E, 0x97D2D988,
    0x09B64C2B, 0x7EB17CBD, 0xE7B82D07, 0x90BF1D91,
    0x1DB71064, 0x6AB020F2, 0xF3B97148, 0x84BE41DE,
    0x1ADAD47D, 0x6DDDE4EB, 0xF4D4B551, 0x83D385C7,
    0x136C9856, 0x646BA8C0, 0xFD62F97A, 0x8A65C9EC,
    0x14015C4F, 0x63066CD9, 0xFA0F3D63, 0x8D080DF5,
    0x3B6E20C8, 0x4C69105E, 0xD56041E4, 0xA2677172,
    0x3C03E4D1, 0x4B04D447, 0xD20D85FD, 0xA50AB56B,
    0x35B5A8FA, 0x42B2986C, 0xDBBBC9D6, 0xACBCF940,
    0x32D86CE3, 0x45DF5C75, 0xDCD60DCF, 0xABD13D59,
    0x26D930AC, 0x51DE003A, 0xC8D75180, 0xBFD06116,
    0x21B4F4B5, 0x56B3C423, 0xCFBA9599, 0xB8BDA50F,
    0x2802B89E, 0x5F058808, 0xC60CD9B2, 0xB10BE924,
    0x2F6F7C87, 0x58684C11, 0xC1611DAB, 0xB6662D3D,
    0x76DC4190, 0x01DB7106, 0x98D220BC, 0xEFD5102A,
    0x71B18589, 0x06B6B51F, 0x9FBFE4A5, 0xE8B8D433,
    0x7807C9A2, 0x0F00F934, 0x9609A88E, 0xE10E9818,
    0x7F6A0DBB, 0x086D3D2D, 0x91646C97, 0xE6635C01,
    0x6B6B51F4, 0x1C6C6162, 0x856530D8, 0xF262004E,
    0x6C0695ED, 0x1B01A57B, 0x8208F4C1, 0xF50FC457,
    0x65B0D9C6, 0x12B7E950, 0x8BBEB8EA, 0xFCB9887C,
    0x62DD1DDF, 0x15DA2D49, 0x8CD37CF3, 0xFBD44C65,
    0x4DB26158, 0x3AB551CE, 0xA3BC0074, 0xD4BB30E2,
    0x4ADFA541, 0x3DD895D7, 0xA4D1C46D, 0xD3D6F4FB,
    0x4369E96A, 0x346ED9FC, 0xAD678846, 0xDA60B8D0,
    0x44042D73, 0x33031DE5, 0xAA0A4C5F, 0xDD0D7CC9,
    0x5005713C, 0x270241AA, 0xBE0B1010, 0xC90C2086,
    0x5768B525, 0x206F85B3, 0xB966D409, 0xCE61E49F,
    0x5EDEF90E, 0x29D9C998, 0xB0D09822, 0xC7D7A8B4,
    0x59B33D17, 0x2EB40D81, 0xB7BD5C3B, 0xC0BA6CAD,
    0xEDB88320, 0x9ABFB3B6, 0x03B6E20C, 0x74B1D29A,
    0xEAD54739, 0x9DD277AF, 0x04DB2615, 0x73DC1683,
    0xE3630B12, 0x94643B84, 0x0D6D6A3E, 0x7A6A5AA8,
    0xE40ECF0B, 0x9309FF9D, 0x0A00AE27, 0x7D079EB1,
    0xF00F9344, 0x8708A3D2, 0x1E01F268, 0x6906C2FE,
    0xF762575D, 0x806567CB, 0x196C3671, 0x6E6B06E7,
    0xFED41B76, 0x89D32BE0, 0x10DA7A5A, 0x67DD4ACC,
    0xF9B9DF6F, 0x8EBEEFF9, 0x17B7BE43, 0x60B08ED5,
    0xD6D6A3E8, 0xA1D1937E, 0x38D8C2C4, 0x4FDFF252,
    0xD1BB67F1, 0xA6BC5767, 0x3FB506DD, 0x48B2364B,
    0xD80D2BDA, 0xAF0A1B4C, 0x36034AF6, 0x41047A60,
    0xDF60EFC3, 0xA867DF55, 0x316E8EEF, 0x4669BE79,
    0xCB61B38C, 0xBC66831A, 0x256FD2A0, 0x5268E236,
    0xCC0C7795, 0xBB0B4703, 0x220216B9, 0x5505262F,
    0xC5BA3BBE, 0xB2BD0B28, 0x2BB45A92, 0x5CB36A04,
    0xC2D7FFA7, 0xB5D0CF31, 0x2CD99E8B, 0x5BDEAE1D,
    0x9B64C2B0, 0xEC63F226, 0x756AA39C, 0x026D930A,
    0x9C0906A9, 0xEB0E363F, 0x72076785, 0x05005713,
    0x95BF4A82, 0xE2B87A14, 0x7BB12BAE, 0x0CB61B38,
    0x92D28E9B, 0xE5D5BE0D, 0x7CDCEFB7, 0x0BDBDF21,
    0x86D3D2D4, 0xF1D4E242, 0x68DDB3F8, 0x1FDA836E,
    0x81BE16CD, 0xF6B9265B, 0x6FB077E1, 0x18B74777,
    0x88085AE6, 0xFF0F6A70, 0x66063BCA, 0x11010B5C,
    0x8F659EFF, 0xF862AE69, 0x616BFFD3, 0x166CCF45,
    0xA00AE278, 0xD70DD2EE, 0x4E048354, 0x3903B3C2,
    0xA7672661, 0xD06016F7, 0x4969474D, 0x3E6E77DB,
    0xAED16A4A, 0xD9D65ADC, 0x40DF0B66, 0x37D83BF0,
    0xA9BCAE53, 0xDEBB9EC5, 0x47B2CF7F, 0x30B5FFE9,
    0xBDBDF21C, 0xCABAC28A, 0x53B39330, 0x24B4A3A6,
    0xBAD03605, 0xCDD70693, 0x54DE5729, 0x23D967BF,
    0xB3667A2E, 0xC4614AB8, 0x5D681B02, 0x2A6F2B94,
    0xB40BBE37, 0xC30C8EA1, 0x5A05DF1B, 0x2D02EF8D,
};

/**
  @brief Calculate CRC32 (IEEE 802.3 standard polynomial).

  @param[in] Data   Input buffer
  @param[in] Length Number of bytes

  @return CRC32 value
**/
UINT32
crc32_calc (
    IN CONST UINT8 *Data,
    IN UINTN        Length
    )
{
    UINT32 crc = 0xFFFFFFFF;

    for (UINTN i = 0; i < Length; i++) {
        UINT8 index = (UINT8)((crc ^ Data[i]) & 0xFF);
        crc = (crc >> 1) ^ Crc32Table[index];
    }

    return crc ^ 0xFFFFFFFF;
}


/**
  @brief Print colored hexdump (offset + hex + ascii) using Print().

  @param[in] Data   Input buffer
  @param[in] Size   Number of bytes
**/
VOID
hexdump_color (
    IN CONST UINT8 *Data,
    IN UINTN        Size
    )
{
    if (Data == NULL || Size == 0)
        return;

    for (UINTN offset = 0; offset < Size; offset += BYTES_PER_LINE) {

        //
        // Offset (Blue)
        //
        Print(C_BLU L"%08X" C_RST L"  ", offset);

        //
        // Hex bytes
        //
        for (UINTN i = 0; i < BYTES_PER_LINE; i++) {

            if (offset + i < Size) {
                Print(L"%02X ", Data[offset + i]);
            } else {
                Print(L"   "); // alignment
            }

            if (i == 7)
                Print(L" ");
        }

        //
        // ASCII representation
        //
        Print(L" |");

        for (UINTN i = 0; i < BYTES_PER_LINE; i++) {

            if (offset + i < Size) {
                UINT8 c = Data[offset + i];

                if (c >= 32 && c <= 126) {
                    Print(C_GRN L"%c" C_RST, c);
                } else {
                    Print(L".");
                }
            } else {
                Print(L" ");
            }
        }

        Print(L"|\n");
    }
}

/* ============================================================
 *  NV index exists / define / undefine / ensure
 * ============================================================ */

/**
  @brief Check whether a TPM NV index exists.

  @param[in]  Index   NV index.
  @param[out] Exists  TRUE if NV index exists, FALSE if not.

  @retval EFI_SUCCESS      Operation completed, Exists is valid.
  @retval EFI_INVALID_PARAMETER  Exists == NULL.
  @retval Others           Error from Tpm2NvReadPublic().
**/
EFI_STATUS
SBC_NvExists (
  IN  TPMI_RH_NV_INDEX Index,
  OUT BOOLEAN         *Exists
  )
{
  EFI_STATUS      Status;
  TPM2B_NV_PUBLIC NvPublic;
  TPM2B_NAME      NvName;

  if (Exists == NULL) {
    return EFI_INVALID_PARAMETER;
  }

  *Exists = FALSE;

  ZeroMem (&NvName, sizeof (NvName));

  Status = Tpm2NvReadPublic (Index, &NvPublic, &NvName);
  if (!EFI_ERROR (Status)) {
    *Exists = TRUE;
//  if (NvPublic != NULL) {
//    FreePool (NvPublic);
//  }
    return EFI_SUCCESS;
  }

  if (Status == EFI_NOT_FOUND) {
    *Exists = FALSE;
    return EFI_SUCCESS;
  }

  DEBUG ((DEBUG_ERROR, "[TPM NV] NvReadPublic(0x%08x) failed: %r\n", Index, Status));
  return Status;
}

/**
  @brief Define NV index with simple owner+auth read/write attributes.

  Owner hierarchy authorizes the DefineSpace and later Write/Read.

  @param[in] Index  NV index.
  @param[in] Size   NV data size in bytes.

  @retval EFI_SUCCESS      Index defined successfully.
  @retval EFI_ALREADY_STARTED Index already defined (NV_DEFINED equivalent).
  @retval Others           Error from Tpm2NvDefineSpace().
**/
EFI_STATUS
SBC_NvDefine (
  IN TPMI_RH_NV_INDEX Index,
  IN UINT16           Size
  )
{
  EFI_STATUS     Status;
  TPM2B_AUTH     Auth;
  TPM2B_NV_PUBLIC NvPub;

  ZeroMem (&Auth, sizeof (Auth));
  Auth.size = 0;  // empty auth

  ZeroMem (&NvPub, sizeof (NvPub));
  NvPub.size                = sizeof (TPMS_NV_PUBLIC);
  NvPub.nvPublic.nvIndex    = Index;
  NvPub.nvPublic.nameAlg    = TPM_ALG_SHA256;
  NvPub.nvPublic.attributes.TPMA_NV_AUTHREAD = 1;
  NvPub.nvPublic.attributes.TPMA_NV_AUTHWRITE = 1;
  NvPub.nvPublic.attributes.TPMA_NV_OWNERREAD = 1;
  NvPub.nvPublic.attributes.TPMA_NV_OWNERWRITE = 1;

  NvPub.nvPublic.dataSize   = Size;
  // IMPORTANT: empty policy, and size fields must be valid
  NvPub.nvPublic.authPolicy.size = 0;

  // IMPORTANT: TPM marshalled size of TPMS_NV_PUBLIC
  // = nvIndex(4) + nameAlg(2) + attributes(4) + authPolicy(2 + N) + dataSize(2)
  // = 14 + authPolicy.size
  NvPub.size = (UINT16)(14u + NvPub.nvPublic.authPolicy.size);


  Status = Tpm2NvDefineSpace (
             TPM_RH_OWNER,   // AuthHandle
             NULL,           // AuthSession (password, empty)
             &Auth,
             &NvPub
           );

  if (Status == EFI_ALREADY_STARTED) {
    DEBUG ((DEBUG_WARN, "[TPM NV] Index 0x%08x already defined.\n", Index));
    return Status;
  }

  if (EFI_ERROR (Status)) {
    DEBUG ((DEBUG_ERROR,
            "[TPM NV] NvDefineSpace(0x%08x, size=%u) failed: %r\n",
            Index, Size, Status));
    return Status;
  }

  DEBUG ((DEBUG_INFO,
          "[TPM NV] Index 0x%08x defined (size=%u).\n",
          Index, Size));
  return EFI_SUCCESS;
}

/**
  @brief Undefine (delete) NV index.

  @param[in] Index  NV index.

  @retval EFI_SUCCESS      Index undefined.
  @retval EFI_NOT_FOUND    Index did not exist.
  @retval Others           Error from Tpm2NvUndefineSpace().
**/
EFI_STATUS
SBC_NvUndefine (
  IN TPMI_RH_NV_INDEX Index
  )
{
  EFI_STATUS Status;

  Status = Tpm2NvUndefineSpace (
             TPM_RH_OWNER,   // AuthHandle
             Index,
             NULL            // AuthSession
           );

  if (Status == EFI_NOT_FOUND) {
    DEBUG ((DEBUG_WARN,
            "[TPM NV] Index 0x%08x does not exist (Undefine).\n",
            Index));
    return Status;
  }

  if (EFI_ERROR (Status)) {
    DEBUG ((DEBUG_ERROR,
            "[TPM NV] NvUndefineSpace(0x%08x) failed: %r\n",
            Index, Status));
    return Status;
  }

  DEBUG ((DEBUG_INFO,
          "[TPM NV] Index 0x%08x undefined.\n",
          Index));
  return EFI_SUCCESS;
}

/**
  @brief Ensure NV index is defined with expected size.

  If the NV index does not exist, this function will define it.

  @param[in] Index  NV index.
  @param[in] Size   NV data size.

  @retval EFI_SUCCESS      Index exists (pre-existing or newly defined).
  @retval Others           TPM error.
**/
EFI_STATUS
SBC_NvEnsureDefined (
  IN TPMI_RH_NV_INDEX Index,
  IN UINT16           Size
  )
{
  EFI_STATUS Status;
  BOOLEAN    Exists;

  Status = SBC_NvExists (Index, &Exists);
  if (EFI_ERROR (Status)) {
    return Status;
  }

  if (Exists) {
    // Already defined, do not redefine.
    return EFI_SUCCESS;
  }

  // Not defined -> create
  return SBC_NvDefine (Index, Size);
}

/* ============================================================
 *  NV slot helper
 * ============================================================ */

/**
  @brief Find NV slot from table by logical name.
**/
SBC_NV_SLOT *
SBC_NvFindSlotByName (
  IN CONST CHAR8 *Name
  )
{
  if (Name == NULL) {
    return NULL;
  }

  for (UINTN i = 0; 
       i < ARRAY_SIZE(g_nv_table); 
       i++) {
    if (AsciiStrCmp (g_nv_table[i].Name, Name) == 0) {
      return &g_nv_table[i];
    }
  }

  return NULL;
}

/* ============================================================
 *  NV write with CRC check
 * ============================================================ */

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
  )
{
  EFI_STATUS           Status;
  TPM2B_MAX_BUFFER  NvWrite;
  UINT32               Crc;
  TPMS_AUTH_COMMAND AuthSession; 

  if ((Slot == NULL) || (Data == NULL)) {
    return EFI_INVALID_PARAMETER;
  }

  if (Size != Slot->Size) {
    DEBUG ((DEBUG_ERROR,
            "[TPM NV] Size mismatch: slot=%u, input=%u\n",
            Slot->Size, Size));
    return EFI_INVALID_PARAMETER;
  }

  if (Size > sizeof (NvWrite.buffer)) {
    DEBUG ((DEBUG_ERROR,
            "[TPM NV] NV buffer too small: slot=%u, max=%u\n",
            Size, (UINT32)sizeof (NvWrite.buffer)));
    return EFI_INVALID_PARAMETER;
  }

  // Compute CRC
  //Crc = crc32_calc (Data, Size);
  Crc = CalculateCrc32((VOID *)Data, Size);
  DEBUG ((DEBUG_INFO,
          "[TPM NV] CRC32(%a) = 0x%08x\n",
          Slot->Name,
          Crc));

  if ((ExpectedCrc != 0) && (Crc != ExpectedCrc)) {
    DEBUG ((DEBUG_ERROR,
            "[TPM NV] CRC mismatch: expected=0x%08x, calc=0x%08x\n",
            ExpectedCrc, Crc));
    return EFI_COMPROMISED_DATA;
  }

  // Ensure NV index exists
  Status = SBC_NvEnsureDefined (Slot->Index, Slot->Size);
  if (EFI_ERROR (Status)) {
    return Status;
  }

  ZeroMem (&NvWrite, sizeof (NvWrite));
  NvWrite.size = Size;
  CopyMem (NvWrite.buffer, Data, Size);



    ZeroMem (&AuthSession, sizeof(AuthSession));
    AuthSession.sessionHandle = TPM_RS_PW;
    AuthSession.nonce.size = 0;
    AuthSession.hmac.size = 0;

  Status = Tpm2NvWrite (
             TPM_RH_OWNER,    // AuthHandle (OWNERWRITE)
             Slot->Index,     // NvIndex
             &AuthSession,            // AuthSession
             &NvWrite,
             0                // Offset
           );

  if (EFI_ERROR (Status)) {
    DEBUG ((DEBUG_ERROR,
            "[TPM NV] NvWrite(%a, 0x%08x) failed: %r\n",
            Slot->Name,
            Slot->Index,
            Status));
    return Status;
  }

  DEBUG ((DEBUG_INFO,
          "[TPM NV] NvWrite %a (0x%08x) size=%u OK\n",
          Slot->Name,
          Slot->Index,
          Size));
  return EFI_SUCCESS;
}

/* ============================================================
 *  NV generic buffer read
 * ============================================================ */

/**
  @brief Read NV data into caller-provided buffer.

  @param[in]  Slot          NV slot descriptor.
  @param[out] OutBuf        Output buffer.
  @param[in]  OutBufSize    Output buffer size in bytes.
  @param[out] OutReadSize   Optional; actual bytes read.

  @retval EFI_SUCCESS            Read OK.
  @retval EFI_INVALID_PARAMETER  Slot/OutBuf invalid or too small.
  @retval EFI_NOT_FOUND          NV index not defined.
  @retval Others                 Error from NV operations.
**/
EFI_STATUS
SBC_NvReadBuffer (
  IN  CONST SBC_NV_SLOT *Slot,
  OUT UINT8             *OutBuf,
  IN  UINT16             OutBufSize,
  OUT UINT16            *OutReadSize OPTIONAL
  )
{
  EFI_STATUS           Status;
  BOOLEAN              Exists;
  TPM2B_MAX_BUFFER  NvRead;

  TPMS_AUTH_COMMAND AuthSession;

  if ((Slot == NULL) || (OutBuf == NULL)) {
    return EFI_INVALID_PARAMETER;
  }

  if (OutBufSize < Slot->Size) {
    DEBUG ((DEBUG_ERROR,
            "[TPM NV] Output buffer too small: needed=%u, got=%u\n",
            Slot->Size,
            OutBufSize));
    return EFI_INVALID_PARAMETER;
  }



  Status = SBC_NvExists (Slot->Index, &Exists);
  if (EFI_ERROR (Status)) {
    return Status;
  }

  if (!Exists) {
    DEBUG ((DEBUG_ERROR,
            "[TPM NV] Index 0x%08x does not exist.\n",
            Slot->Index));
    return EFI_NOT_FOUND;
  }

  ZeroMem (&NvRead, sizeof (NvRead));

    ZeroMem(&AuthSession, sizeof(AuthSession));

    AuthSession.sessionHandle = TPM_RS_PW;
    AuthSession.nonce.size = 0;
    AuthSession.hmac.size = 0;

  Status = Tpm2NvRead (
             TPM_RH_OWNER,   // AuthHandle
             Slot->Index,    // NvIndex
             &AuthSession,           // AuthSession
             Slot->Size,     // Size
             0,              // Offset
             &NvRead
           );

  if (EFI_ERROR (Status)) {
    DEBUG ((DEBUG_ERROR,
            "[ERR TPM NV] NvRead(%a, 0x%08x) Size=%u failed: %r\n",
            Slot->Name,
            Slot->Index,
            Slot->Size,
            Status));
    return Status;
  }

  DEBUG((DEBUG_INFO,
         "[INFO TPM NV] NvRead(%a, 0x%08x) Size=%u failed: %r\n",
         Slot->Name,
         Slot->Index,
         Slot->Size,
         Status)); 

  CopyMem (OutBuf, NvRead.buffer, NvRead.size);
  if (OutReadSize != NULL) {
    *OutReadSize = NvRead.size;
  }

  return EFI_SUCCESS;
}

/**
  @brief Read NV data and print colored hexdump (using existing hexdump_color()).

  @retval EFI_SUCCESS            Hexdump printed.
  @retval Others                 Error from SBC_NvReadBuffer().
**/
EFI_STATUS
SBC_NvReadHexdump (
  IN CONST SBC_NV_SLOT *Slot
  )
{
  EFI_STATUS Status;
  UINT8     *Buf;
  UINT16     ReadSize;

  if (Slot == NULL) {
    return EFI_INVALID_PARAMETER;
  }

  Buf = AllocateZeroPool (Slot->Size);
  if (Buf == NULL) {
    return EFI_OUT_OF_RESOURCES;
  }

  Status = SBC_NvReadBuffer (Slot, Buf, Slot->Size, &ReadSize);
  if (EFI_ERROR (Status)) {
    FreePool (Buf);
    return Status;
  }

  DEBUG ((DEBUG_INFO,
          "\n[TPM NV] NvRead %a (0x%08x) size=%u\n",
          Slot->Name,
          Slot->Index,
          ReadSize));

  hexdump_color (Buf, ReadSize);

  FreePool (Buf);
  return EFI_SUCCESS;
}
