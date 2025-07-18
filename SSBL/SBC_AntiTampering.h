#ifndef _SBC_ANTITAMPERING_
#define _SBC_ANTITAMPERING_

#define STR_FSBL_F_NAME             L"FS1:\\EFI\\BOOT\\FSBL.efi"
#define SBC_AT_HASH_LEN             32

/*!
    \defgroup DigestSystem
    \{
*/
/*!
    \brief Anti-tampering DICE key strength 
*/
#define ATP_IDENT_KEY_STG          32
#pragma pack(1)
/*!
 * Anti-tampering Identify for DICE key
 * 
 * \author leoc (6/9/25)
 */
typedef struct {
    UINT8           devid[ATP_IDENT_KEY_STG];   //! Device ID 
    UINT8           fwid[ATP_IDENT_KEY_STG];    //! Firmware ID
    UINT8           osid[ATP_IDENT_KEY_STG];    //! OS ID 
}atp_ident_t;
#pragma pack()


#pragma pack(1)
typedef struct _hw_unique_info_t {
    UINT8   mbsn[64];               /*!< Motherboard serail */
    UINTN   mbsnl;
    UINT8   mmsn[64];               //! Memory serial 
    UINTN   mmsnl;
    UINT8   nvmesn[64];             ///< SSD serial 
    UINTN   nvmesnl;                /*!< Length of  SSD serial */
    //at_key_t *key;
}hw_uniqueinfo_t;

typedef struct _fhnd_img_t {
    UINT32  fsbln;
    UINTN   fsbladdr;        // Address pointing to where the LSBL image is.
    UINT32  ssbln;
    UINTN   ssbladdr;        // Address pointing to where the LSBL image is.

}fhnd_img_t;
#pragma pack()
/*! \}*/

/*!
    \defgroup BaseAnswer In terms of the Base Answer behavior
    \{
*/

#define BASE_ANS_MAX_LEN            256
#define BASE_ANS_KEY_STR            32      /**< Base Answer Encrypt/Decrypt Key Strength */
#define BASE_ANS_IV_KEY_STR         12      /**< Base Answer IV size */
#define BASE_ANS_TAG_LEN            16      /**< Base Answer TAG size */
#define BASE_ANS_BLK_LBA            0
#define BASE_ANS_SAT_OFFSET         0x100 // 256
#define BASE_ANS_STREAM_LEN         512
#define BASE_ANS_BLK_LEN            512


#pragma pack(1)
/*!
 * \struct base_ansid_t is used to identify the Base Answer 

 * \author leoc (6/5/25)
 */
typedef struct _base_ansid_t {
    UINT32  msglen;                             //! Length of Encrypted Base Answer string 
    UINT8   encmsg[BASE_ANS_MAX_LEN];           //! Encrypted base answer message
    UINT8   key[BASE_ANS_KEY_STR];              //! Base Answer decrypt key
    UINT8   iv[BASE_ANS_IV_KEY_STR];            //! Base Answer decrypt IV value
    UINT8   tag[BASE_ANS_TAG_LEN];              //! Base Answer decrypt TAG which used in the AES GCM Mode
}base_ansid_t;

#pragma pack()
/*! } */



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
SBCStatus SBC_BaseAnswerEncryptStore(UINT8* msg, UINT32 msgl, UINT8 *key, UINT32 keyl);


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

SBCStatus SBC_GenOSID(EFI_HANDLE *h_image, UINT8 *fwid, UINT8 *osid);



#endif
