#ifndef _SBC_ANTITAMPERING_
#define _SBC_ANTITAMPERING_

#ifndef _FSBL_TEST_
#   define OSID_KERNEL_PATH            L"\\vmlinuz"            
#else
#   define OSID_KERNEL_PATH            L"\\vmlinuz" 
#endif

#ifndef _FSBL_TEST_
#   define STR_FSBL_F_NAME             L"\\EFI\\BOOT\\bootx64.efi"
#   define STR_SSBL_F_NAME             L"\\EFI\\BOOT\\SSBL.efi"
#else
#   define STR_FSBL_F_NAME             L"\\EFI\\BOOT\\FSBL.efi"
#endif

#define SBC_AT_IV_LEN               12
#define SBC_AT_HASH_LEN             32
#define SBC_BLKDEV_BLKSZ            512

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
    UINT8           migid[ATP_IDENT_KEY_STG];    //! Migration key ID
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

#define BASE_ANSW_DEFLEN            16
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

/*!
  \defgroup IntegrityCheck
  \{
 */
#define SBC_INTG_BLOCK_LAB                      4
#define SBC_INTG_CRET_SKIP                      0x20


/*! \}*/

#define FSBL_BNIFO_SIZE                         8

#pragma pack(1)
typedef union _t_fsbl_bsifo {

    struct {
        UINT32 siglen:8;            /// Signature Length
        UINT32 fwinfolen:8;         /// Firmware Info Length
        UINT32 certlen:16;          /// Ceritiface length
        UINT32 banswlen:8;          /// Base-answer length
        UINT32 bsinfv:8;            /// Version of BSinfo
        UINT32 reserv1:8;
        UINT32 reserv2:8;
    }m;

    UINT8   value[FSBL_BNIFO_SIZE];
}fsbl_bsinfo_t;

typedef struct _t_fsbl_bsinfo_ptr {
    VOID *baseansw;
    VOID *fwinfo;
    VOID *certi;
    VOID *signature;
}fsbl_bsinfo_ptr_t;

typedef struct _t_mig_key {
    UINT8 key[SBC_AT_HASH_LEN];
    UINT32 fsbl_pres_bank;
    UINT32 ssbl_pres_bank;
    UINT32 os_pres_bank;
}mig_key_t;

typedef struct _t_baseansr {
    //UINT32  len;
    //VOID    *key;
    VOID    *iohndl;
    VOID    *iv;
    VOID    *tag;
    VOID    *msg;           /*! Encrypted message */
    UINTN   msglen;
}baseansr_t;
#pragma pack()


/*!
 * \fn VOID SBC_AntiTamperingInit(VOID *priv)
 * 
 * \author leoc (9/2/25)
 * 
 * \param priv   Point to Boot Procedure related object
 */
VOID SBC_AntiTamperingInit(VOID *priv);

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
SBCStatus SBC_BaseAnswerEncryptStore(VOID *blkhnd, UINT8* msg, UINT32 msgl, UINT8 *key, UINT32 keyl);


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
SBCStatus  SBC_BaseAnswerValidate(VOID *blkhnd, UINT8 *answer, UINTN answerl, UINT8 *key, UINTN keylen);

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
SBCStatus SBC_GenFWID(EFI_HANDLE *h_image, UINT8 *devid, UINT8 *fwid, UINTN normbank, UINTN bm);

SBCStatus SBC_GenOSID(EFI_HANDLE *h_image, UINT8 *fwid, UINT8 *osid);


SBCStatus  SBC_FSBLIntgCheck(EFI_HANDLE *h_image , VOID *blkio, VOID *cert, UINTN certlen, UINTN nrombank, UINTN mode);

/*!
 * \fn SBCStatus  SBC_FSBL_Verify(VOID *blkhnd, VOID *ansr, UINTN normbank, UINTN bm, UINT16 *fblpath)
 * 
 * \brief Verify the FSBL signature
 * 
 * \author leoc (9/2/25)
 * 
 * \param blkhnd   Indicates a pointer to the calling context
 * \param ansr     Pointer to buffer for the base-answer destination  data. 
 * \param nrombank Indicates a normal firmware bank
 * \param bm       Indicates the curtently boot mode 
 * \param fname    Pointer to the filename for opening ( Used only in test mode )
 * 
 * \return On Success, return the SBCOK, otherwise,return the apporiate value. 
 */
SBCStatus  SBC_FSBL_Verify(VOID *blkhnd, VOID *ansr, UINTN normbank, UINTN bm, UINT16 *fblpath);

SBCStatus  SBC_BlkIoHandleInit(OUT VOID **hblk, OUT VOID *hdr);

SBCStatus  SBC_GenMigrationKey(VOID *priv, UINT32 currbankid, UINT32 prevbankid, VOID *out);

/*!
 * \fn SBCStatus  SBC_DeviceIdKyeVerify(VOID *blkio, UINT8 *devid, UINT8 *deckey)
 * 
 * \brief Verify certificate was issued by RootCA
 * 
 * \author leoc (7/10/25)
 * 
 * \param blkio  Indicates a pointer to the calling context
 * \param devid  Pointer to buffer for the device id
 * \param deckey Pointer to buffer for decryption 
 * 
 * \return On Success, return the SBCOK, otherwise,return the apporiate value. 
 */
SBCStatus  SBC_DeviceIdKyeVerify(VOID *blkio, UINT8 *devid, UINT8 *deckey);

/*!
 * \fn SBCStatus  SBC_SSBL_Verify(VOID *blkhnd, VOID *ansr,  UINTN nrombank, UINTN bm, CHAR16 *fname)
 * 
 * \brief Verify the SSBL signature
 * 
 * \author leoc (9/2/25)
 * 
 * \param blkhnd   Indicates a pointer to the calling context
 * \param ansr     Pointer to buffer for the base-answer destination  data. 
 * \param nrombank Indicates a normal firmware bank
 * \param bm       Indicates the curtently boot mode 
 * \param fname    Pointer to the filename for opening ( Used only in test mode )
 * 
 * \return On Success, return the SBCOK, otherwise,return the apporiate value. 
 */
SBCStatus  SBC_SSBL_Verify(VOID *blkhnd, VOID *ansr,  UINTN nrombank, UINTN bm, CHAR16 *fname);

/*!
 * \fn SBCStatus  SBC_Vmlinuz_Verify(VOID *blkhnd, VOID *ansr, UINTN normbank, UINTN bm, UINT16 *fblpath)
 * 
 * \brief Verify the Vmlinuz signature
 * 
 * \author leoc (9/2/25)
 * 
 * \param blkhnd   Indicates a pointer to the calling context
 * \param ansr     Pointer to buffer for the base-answer destination  data. 
 * \param nrombank Indicates a normal firmware bank
 * \param bm       Indicates the curtently boot mode 
 * \param fname    Pointer to the filename for opening ( Used only in test mode )
 * 
 * \return On Success, return the SBCOK, otherwise,return the apporiate value. 
 */
SBCStatus  SBC_Vmlinuz_Verify(VOID *blkhnd, VOID *ansr, UINTN normbank, UINTN bm, UINT16 *fblpath);


SBCStatus SBC_DeviceSecuirtyKeyCreate(VOID *key);
SBCStatus SBC_ReadFwBootSrvInformation(UINT16 *flbpath, VOID *blobinfo, VOID *szinfo);
#endif
