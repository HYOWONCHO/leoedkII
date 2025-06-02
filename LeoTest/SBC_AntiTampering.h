#ifndef _SBC_ANTITAMPERING_
#define _SBC_ANTITAMPERING_

#define STR_FSBL_F_NAME             L"FS1:\\EFI\\BOOT\\FSBL.efi"
#define SBC_AT_HASH_LEN             32

#pragma pack(1)
typedef struct _hw_unique_info_t {
    UINT8   mbsn[64];            /*!< Motherboard serail */
    UINTN   mbsnl;
    UINT8   mmsn[64];            /*!< Memory serial */
    UINTN   mmsnl;
    UINT8   nvmesn[64];            /*!< SSD serial */
    UINTN   nvmesnl;           /*!< Length of  SSD serial */
    //at_key_t *key;
}hw_uniqueinfo_t;

typedef struct _fhnd_img_t {
    UINT32  fsbln;
    UINTN   fsbladdr;        // Address pointing to where the LSBL image is.
    UINT32  ssbln;
    UINTN   ssbladdr;        // Address pointing to where the LSBL image is.

}fhnd_img_t;
#pragma pack()


SBCStatus SBC_GenDeviceID(UINT8 *devid);
SBCStatus SBC_BaseAnswerEncryptStore(UINT8 *out, UINTN *outl);
SBCStatus  SBC_BaseAnswerValidate(UINT8 *answer, UINTN answerl);
SBCStatus SBC_GenFWID(EFI_HANDLE *h_image, UINT8 *devid, UINT8 *fwid);

#endif
