/********************************************************************************
 * Copyright (C) 2024 by Security Platform Inc.                                 *
 * This file is part of the Project.                                            *
 *                                                                              *
 * This software contains confidential and proprietary information of           *
 * Security Platform Inc. Unauthorized reproduction, distribution, or           *
 * disclosure of this software, in whole or in part, is strictly prohibited.    *
 ********************************************************************************/

#ifndef _SBC_ANTITAMPERING_
#define _SBC_ANTITAMPERING_


#define KERNEL_DIR_FILE                L"\\EFI\\BOOT\\kernel_path.txt"

#ifndef _SSBL_TEST_
#   define OSID_KERNEL_PATH            L"\\vmlinuz"         
#   define EFI_BOOT_FSBL_PATH          L"\\EFI\\BOOT\\FSBL.efi"
#   define EFI_BOOT_SSBL_PATH          L"\\EFI\\BOOT\\SSBL.efi"
#else
#   define OSID_KERNEL_PATH            L"\\vmlinuz"         
#   define EFI_BOOT_FSBL_PATH          L"\\EFI\\BOOT\\FSBL.efi.bin"
#   define EFI_BOOT_SSBL_PATH          L"\\EFI\\BOOT\\SSBL.efi.bin"
#endif

#define SBC_AT_HASH_LEN             32
#define SBC_AT_IV_LEN               12
#define SBC_AT_TAG_LEN              16
#define SBC_BLKDEV_BLKSZ            512

#define SBC_BASE_ANSR_LEN           16
#define SBC_OSID_KEY_LEN            32

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
 * \brief Initializes the Anti-Tampering context and module 
 * 
 * \author leonc (10/31/25)
 * 
 * \param[in] priv   Pointer to a boot_proc_t structure containing initialization 
 * \retrun None
 */
VOID SBC_AntiTamperInit(VOID *priv);

/*!
 * \brief De-Initializes the Anti-Tampering context and module 
 * 
 * \author leonc (10/31/25)
 * 
 * \param[in] priv   Pointer to a boot_proc_t structure containing initialization 
 * \retrun None
 */
VOID SBC_AntiTamperDeinit(VOID *priv);

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
//SBCStatus  SBC_BaseAnswerValidate(VOID *blkhnd, UINT8 *answer, UINTN answerl, UINT8 *key, UINTN keylen);
SBCStatus  SBC_BaseAnswerValidate(VOID *blkhnd, UINT8 *answer, UINTN answerl, UINT8 *key, UINTN keylen, BOOLEAN ischeck);
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


/**
 * @fn SBCStatus SBC_GenOSID(EFI_HANDLE *h_image, UINT8 *fwid,
 *     UINT8 *osid)
 * 
 * @author leoc (6/2/25)
 * 
 * @param h_image EFI Image Handle
 * @param devid   Pointer to Firmware ID buffer where computed 
 * @param osid    Pointer to OS ID buffer 
 * 
 * @return On Success, return the SBCOK, otherwise, return the apporiate error
 *         value.
 */
SBCStatus SBC_GenOSID(EFI_HANDLE *h_image, UINT8 *fwid, UINT8 *osid);

/*!
 * \fn SBCStatus  SBC_FSBLIntgCheck(EFI_HANDLE *h_image ,
   VOID *blkio, VOID *cert, UINTN certlen, UINTN nrombank,
   UINTN mode)
 * 
 * \author leonc (10/31/25)
 * 
 * \param h_image  Unused EFI Image handle  ( reserved for
   future use)
 * \param blkio    Pointer to a EFI_BLOCK_IO_PROTOCOL
 * \param cert     Pointer to a Root CA
 * \param certle   Length of Cert. in bytes
 * \param nrombank Bank ID for SSBL Firmware of Raw-partition
 * \param mode     Boot Mode indicator
 * 
 * \return SBCStatus
 *          - SBCOK : Verification Succeeded
 *          - SBCINVPARAM : Invalid Parameters
 *          - SBCNULLP : Memory Allocation fail
 *          
 */
SBCStatus  SBC_FSBLIntgCheck(EFI_HANDLE *h_image , VOID *blkio, VOID *cert, UINTN certle, UINTN nrombank, UINTN mode);


SBCStatus  SBC_FSBL_Verify(VOID *blkhnd, VOID *ansr, UINTN normbank, UINTN bm);

SBCStatus  SBC_BlkIoHandleInit(OUT VOID **hblk, OUT VOID *hdr);

//SBCStatus  SBC_GenMigrationKey(VOID *priv, UINT32 currbankid, UINT32 prevbankid, VOID *out);

/**
 * @fn SBC_GenMigrationKey
 * @brief Generates a migration key based on hardware identifiers and firmware hashes.
 *
 * This function collects hardware-unique information (baseboard, memory, NVMe serials),
 * reads FSBL and SSBL firmware images from both EFI and raw partitions, computes their hashes,
 * and combines all data into a single digest to produce a migration key.
 *
 * @param[in]  priv     Pointer to boot_proc_t structure containing boot context and block handle.
 * @param[out] outmsg   Pointer to buffer where the final migration key (hash digest) will be stored.
 *
 * @return SBCStatus
 *         - SBCOK: Migration key generated successfully.
 *         - SBCNULLP: Memory allocation failure or null pointer.
 *         - SBCINVPARAM: Invalid input or missing firmware.
 *         - Other error codes from internal hash or file read failures.
 *
 */
SBCStatus SBC_GenMigrationKey(void *priv, void *outmsg);

/**
 * @fn SBC_DeviceIdKyeVerify
 * @brief Verifies the device identity by comparing the generated public key with the decrypted certificate key.
 *
 *
 * @param[in] blkio   Pointer to the EFI_BLOCK_IO_PROTOCOL used to access the device storage.
 * @param[in] devid   Pointer to the device ID used to generate the key pair.
 * @param[in] deckey  Pointer to the decryption key used for AES-GCM decryption of the certificate.
 *
 * @return SBCStatus
 *         - SBCOK: Verification succeeded.
 *         - SBCNULLP: Memory allocation failure.
 *         - SBCDECFAIL: Decryption failed.
 *         - SBCINVPARAM: Key generation or public key mismatch.
 *         - SBCFAIL: Public key extraction failure.
 */
SBCStatus  SBC_DeviceIdKyeVerify(VOID *blkio, UINT8 *devid, UINT8 *deckey);

/*!
 * System Setting infomation is encrypt and decrypt 
 * 
 * \author leonc (8/28/25)
 * 
 * \param key    
 * 
 * \return SBCStatus 
 */
SBCStatus SBC_DeviceSecuirtyKeyCreate(VOID *key);


/**
 * @fn SBC_SSBL_Verify
 * 
 * @author leonc (10/31/25)
 * 
 * @param[in]  blkhnd     Pointer to the block I/O handle 
 * @param[out] ansr       Pointer to an LV_t structure to receive the base answer data.
 * @param[in]  normbank   Firmware bank ID of Raw-Partition 
 * @param[in]  bm         Boot mode indicator 
 * 
 * @return SBCStatus
 *         - SBCOK: SSBL verification succeeded.
 *         - SBCNULLP: Memory allocation failure.
 *         - SBCFAIL: Signature verification or public key extraction failed.
 *         - SBCIO: File I/O error during SSBL read.
 */
SBCStatus  SBC_SSBL_Verify(VOID *blkhnd, VOID *ansr,  UINTN nrombank, UINT16 bm);

/*!
 * \fn SBCStatus SBC_DiceIDKeyVerify(VOID *priv)
 * 
 * \brief FWID and OSID certificate verification 
 * 
 * \author leoc (9/18/25)
 * 
 * \param[in] priv   Pointer to Boot Process Structure 
 * 
 * \return On success, return the SBCOK, otherwise, return the approiate error value  
 */
SBCStatus SBC_DiceIDKeyVerify(VOID *priv);
#endif
