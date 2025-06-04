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



/**
 * @fn SBCStatus SBC_GenDeviceID(UINT8 *devid)
 * 
 * Creation the Device ID 
 * 
 * @author leoc (6/2/25)
 * 
 * @param devid  Pointer to Device ID buffer
 * 
 * @return On Success, return the SBCOK, otherwise, return the apporiate error
 *         value.
 * @note
 * Device ID = HASH_SHA256(Base Board SN || Memory SN || NVME SSD SN || FSLBL
 * stream)
 */
SBCStatus SBC_GenDeviceID(UINT8 *devid);

/**
 * @fn SBCStatus SBC_BaseAnswerEncryptStore(UINT8 *out, UINTN *outl)
 * 
 * Base Answer is encrypt, and then, It is sotring in the specified location of
 * Raw Partition
 * 
 * @author leoc (6/2/25)
 * 
 * @param out    
 * @param outl   
 * 
 * @return On Success, return the SBCOK, otherwise, return the apporiate error
 *         value. 
 */
SBCStatus SBC_BaseAnswerEncryptStore(UINT8 *out, UINTN *outl);


/**
 * Base answer is compare with that readed in stored in the RAW partition.
 * 
 * @author leoc (6/2/25)
 * 
 * @param answer  
 * @param answerl 
 * 
 * @return On Success, return the SBCOK, otherwise, return the apporiate error
 *         value. 
 */
SBCStatus  SBC_BaseAnswerValidate(UINT8 *answer, UINTN answerl);

/**
 * @fn SBCStatus SBC_GenFWID(EFI_HANDLE *h_image, UINT8 *devid, UINT8 *fwid)
 * 
 * @author leoc (6/2/25)
 * 
 * @param h_image EFI Image Handle
 * @param devid   Pointer to Device ID buffer where computed 
 * @param fwid    Pointer to FW ID buffer 
 * 
 * @return On Success, return the SBCOK, otherwise, return the apporiate error
 *         value.
 */
SBCStatus SBC_GenFWID(EFI_HANDLE *h_image, UINT8 *devid, UINT8 *fwid);

#endif
