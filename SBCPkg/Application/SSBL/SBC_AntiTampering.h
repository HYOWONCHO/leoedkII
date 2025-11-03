/********************************************************************************
 * Copyright (C) 2024 by Security Platform Inc.                                 *
 * This file is part of the SBC Project.                                        *
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

/**
 * @def SBC_AT_HASH_LEN
 * @brief Length of the authentication hash (in bytes).
 *
 * Defines the size of the hash value used for message authentication,
 * typically corresponding to a SHA-256 digest.
 */
#define SBC_AT_HASH_LEN             32

/**
 * @def SBC_AT_IV_LEN
 * @brief Length of the AES-GCM initialization vector (IV) in bytes.
 *
 * The IV is a 12-byte nonce required for AES-GCM encryption to ensure
 * uniqueness of each encryption operation.
 */
#define SBC_AT_IV_LEN               12

/**
 * @def SBC_AT_TAG_LEN
 * @brief Length of the AES-GCM authentication tag (in bytes).
 *
 * The authentication tag (TAG) is a 16-byte value appended to the ciphertext
 * to verify data integrity and authenticity during decryption.
 */
#define SBC_AT_TAG_LEN              16

/**
 * @def SBC_BLKDEV_BLKSZ
 * @brief Default block size for block device operations (in bytes).
 *
 * Defines the standard I/O block size for aligned read/write operations
 * on block devices used by the SBC platform.
 */
#define SBC_BLKDEV_BLKSZ            512

/**
 * @def SBC_BASE_ANSR_LEN
 * @brief Base answer length used in authentication (in bytes).
 *
 * Defines the size of the fundamental response message or challenge-response
 * payload used in secure authentication procedures.
 */
#define SBC_BASE_ANSR_LEN           16

/**
 * @def SBC_OSID_KEY_LEN
 * @brief Length of the OSID security key (in bytes).
 *
 * Defines the key length used for OS-specific encryption or authentication.
 * Typically corresponds to a 256-bit AES key (32 bytes).
 */
#define SBC_OSID_KEY_LEN            32

/*!
    \defgroup DigestSystem
    \{
*/

/**
 * @def ATP_IDENT_KEY_STG
 * @brief Length of the identification key storage (in bytes).
 */
#define ATP_IDENT_KEY_STG          32

#pragma pack(1)
/**
 * @struct atp_ident_t
 * @brief Anti-tampering identification structure for DICE key.
 */
typedef struct {
    UINT8 devid[ATP_IDENT_KEY_STG];   /**< Device ID - Unique identifier for the hardware device. */
    UINT8 fwid[ATP_IDENT_KEY_STG];    /**< Firmware ID - Identifier derived from firmware image or version. */
    UINT8 osid[ATP_IDENT_KEY_STG];    /**< OS ID - Identifier for the operating system or boot layer. */
    UINT8 migid[ATP_IDENT_KEY_STG];   /**< Migration key ID - Identifier used for secure migration or rekeying. */
} atp_ident_t;
#pragma pack()


#pragma pack(1)
/**
 * @struct hw_uniqueinfo_t
 * @brief Hardware unique information structure.
 *
 * This structure stores hardware-unique serial numbers and identifiers
 * that are used for device authentication, hardware binding, or
 * secure key derivation.  
 */
typedef struct _hw_unique_info_t {
    UINT8 mbsn[64];    /**< Motherboard serial number (UTF-8 or binary). */
    UINTN mbsnl;       /**< Length of the motherboard serial number. */

    UINT8 mmsn[64];    /**< Memory module serial number. */
    UINTN mmsnl;       /**< Length of the memory serial number. */

    UINT8 nvmesn[64];  /**< NVMe or SSD serial number. */
    UINTN nvmesnl;     /**< Length of the NVMe/SSD serial number. */

    // at_key_t *key;   /**< Optional pointer to associated device key (reserved). */
} hw_uniqueinfo_t;

/**
 * @struct fhnd_img_t
 * @brief Boot image handle structure for FSBL and SSBL.
 *
 * This structure holds the memory address and size information
 * of the FSBL (First Stage Boot Loader) and SSBL (Second Stage Boot Loader)
 * images used during the SBC boot process.
 */
typedef struct _fhnd_img_t {
    UINT32 fsbln;        /**< Length of the FSBL image, in bytes. */
    UINTN  fsbladdr;     /**< Memory address where the FSBL image is located. */
    UINT32 ssbln;        /**< Length of the SSBL image, in bytes. */
    UINTN  ssbladdr;     /**< Memory address where the SSBL image is located. */
} fhnd_img_t;
#pragma pack()
/*! \}*/

/*!
    \defgroup BaseAnswer In terms of the Base Answer behavior
    \{
*/

/**
 * @def BASE_ANSW_DEFLEN
 * @brief Default length of the base answer (in bytes).
 *
 * Defines the standard size of the base answer payload used in
 * authentication or secure key exchange.
 */
#define BASE_ANSW_DEFLEN            16

/**
 * @def BASE_ANS_MAX_LEN
 * @brief Maximum supported base answer length (in bytes).
 *
 * Specifies the upper limit of the base answer buffer to prevent
 * overflow or excessive memory allocation.
 */
#define BASE_ANS_MAX_LEN            256

/**
 * @def BASE_ANS_KEY_STR
 * @brief Base Answer encryption/decryption key strength (in bytes).
 *
 * Defines the size of the AES-GCM key used for Base Answer encryption
 * and decryption. A value of 32 bytes represents a 256-bit key strength.
 */
#define BASE_ANS_KEY_STR            32      /**< Base Answer Encrypt/Decrypt Key Strength */

/**
 * @def BASE_ANS_IV_KEY_STR
 * @brief Initialization Vector (IV) size for Base Answer encryption (in bytes).
 *
 * Defines the IV length used in AES-GCM encryption for Base Answer
 * operations. The standard IV size is 12 bytes.
 */
#define BASE_ANS_IV_KEY_STR         12      /**< Base Answer IV size */

/**
 * @def BASE_ANS_TAG_LEN
 * @brief Authentication tag length for AES-GCM encryption (in bytes).
 *
 * Defines the size of the authentication tag appended to encrypted
 * Base Answer data. A 16-byte tag is typical for AES-GCM integrity verification.
 */
#define BASE_ANS_TAG_LEN            16      /**< Base Answer TAG size */

/**
 * @def BASE_ANS_BLK_LBA
 * @brief Logical Block Address (LBA) index for Base Answer storage.
 *
 * Indicates the starting LBA address where Base Answer data is stored
 * on the block device.
 */
#define BASE_ANS_BLK_LBA            0

/**
 * @def BASE_ANS_SAT_OFFSET
 * @brief Offset position for Base Answer storage area (in bytes).
 *
 * Specifies the offset (0x100 = 256 bytes) from the base block address
 * to the start of the Base Answer data region.
 */
#define BASE_ANS_SAT_OFFSET         0x100   /**< Offset (256 bytes) */

/**
 * @def BASE_ANS_STREAM_LEN
 * @brief Length of the Base Answer data stream (in bytes).
 *
 * Defines the total length of the encrypted data stream used in Base
 * Answer operations.
 */
#define BASE_ANS_STREAM_LEN         512

/**
 * @def BASE_ANS_BLK_LEN
 * @brief Base Answer block size (in bytes).
 *
 * Defines the block I/O size used for read and write operations related
 * to Base Answer data storage.
 */
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
/**
 * @union fsbl_bsinfo_t
 * @brief FSBL and SSBL Boot Security Information structure.
 */
typedef union _t_fsbl_bsifo {

    /**
     * @brief Member field representation of Boot Security Info.
     */
    struct {
        UINT32 siglen    : 8;   /**< Signature length (in bytes). */
        UINT32 fwinfolen : 8;   /**< Firmware info length (in bytes). */
        UINT32 certlen   : 16;  /**< Certificate length (in bytes). */
        UINT32 banswlen  : 8;   /**< Base-answer data length (in bytes). */
        UINT32 bsinfv    : 8;   /**< Boot Security Info structure version. */
        UINT32 reserv1   : 8;   /**< Reserved field for alignment/future use. */
        UINT32 reserv2   : 8;   /**< Reserved field for alignment/future use. */
    } m;                        /**< Bitfield view of Boot Security Info. */

    UINT8 value[FSBL_BNIFO_SIZE]; /**< Raw byte array representation for serialization. */
} fsbl_bsinfo_t;


/**
 * @struct fsbl_bsinfo_ptr_t
 * @brief (Deprecated) Pointer mapping for FSBL Boot Security Information.
 *
 * @deprecated
 * This structure is currently **not in use**.
 * Direct memory access to individual BSInfo fields or unified structures
 * (e.g., @ref fsbl_bsinfo_t) are now preferred.
 *
 * @note
 * It may be removed or refactored in future releases.
 */
typedef struct _t_fsbl_bsinfo_ptr {
    VOID *baseansw;     /**< Pointer to Base Answer data region. */
    VOID *fwinfo;       /**< Pointer to firmware information structure. */
    VOID *certi;        /**< Pointer to certificate data region. */
    VOID *signature;    /**< Pointer to digital signature data region. */
} fsbl_bsinfo_ptr_t;


/**
 * @struct mig_key_t
 * @brief (Deprecated) Migration key information structure.
 *
 * @deprecated
 * This structure is currently **not in use**.
 * Key migration functionality has been integrated or replaced by
 * higher-level key management mechanisms.
 *
 * @note
 * It may be removed or refactored in future releases.
 */
typedef struct _t_mig_key {
    UINT8  key[SBC_AT_HASH_LEN];  /**< Migration key (32-byte hash or AES key). */
    UINT32 fsbl_pres_bank;        /**< FSBL key storage bank index. */
    UINT32 ssbl_pres_bank;        /**< SSBL key storage bank index. */
    UINT32 os_pres_bank;          /**< OS key storage bank index. */
} mig_key_t;

/**
 * @struct baseansr_t
 * @brief (Deprecated) Base Answer encryption data structure
 *
 * @deprecated
 * This structure is currently **not in use**.
 * Base Answer encryption is now managed through direct function-level
 * parameters or encapsulated in higher-level secure storage APIs.
 *
 * 
 * @note It may be removed or refactored in future releases.
 */
typedef struct _t_baseansr {
    VOID  *iohndl;   /**< Handle to I/O or block device used for encryption. */
    VOID  *iv;       /**< Pointer to initialization vector (IV). */
    VOID  *tag;      /**< Pointer to authentication tag for AES-GCM. */
    VOID  *msg;      /**< Encrypted message buffer. */
    UINTN msglen;    /**< Length of the encrypted message, in bytes. */
} baseansr_t;
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
 * @fn SBCStatus SBC_BaseAnswerEncryptStore(VOID *blkhnd, UINT8* msg, UINT32 msgl, UINT8 *key, UINT32 keyl)
 * @brief Encrypt and store a message using the provided security key.
 *
 * @param[in]  blkhnd   Pointer to the block I/O or storage handle where the
 *                      encrypted message will be written.
 * @param[in]  msg      Pointer to the plain message buffer to be encrypted.
 * @param[in]  msgl     Length of the message buffer @p msg, in bytes.
 * @param[in]  key      Pointer to the encryption key buffer.
 * @param[in]  keyl     Length of the encryption key buffer @p key, in bytes.
 *
 * @retval SBCOK         Message successfully encrypted and stored.
 * @retval SBCFAIL       Encryption or storage operation failed.
 * @retval SBCNULLP      One or more input pointers are NULL.
 * @retval SBCIO         Device or I/O failure occurred during storage.
 * @retval SBCINVPARAM   Invalid parameter (e.g., zero length or invalid handle).
 */
SBCStatus SBC_BaseAnswerEncryptStore(VOID *blkhnd, UINT8* msg, UINT32 msgl, UINT8 *key, UINT32 keyl);


/**
 * @fn SBCStatus SBC_BaseAnswerValidate(VOID *blkhnd, UINT8 *answer, UINTN answerl, UINT8 *key, UINTN keylen, BOOLEAN ischeck)
 * @brief Validate the device authentication answer using the provided key.
 *
 * @param[in]  blkhnd   Pointer to the block I/O or device handle used for validation.
 * @param[in]  answer   Pointer to the answer buffer received from the device or host.
 * @param[in]  answerl  Length of the @p answer buffer, in bytes.
 * @param[in]  key      Pointer to the security key used for validation.
 * @param[in]  keylen   Length of the @p key buffer, in bytes.
 * @param[in]  ischeck  Boolean flag indicating whether to perform strict validation.
 *                      - TRUE : Perform full verification (compare with expected digest)
 *                      - FALSE: Do not perform verification, just copy the
 *                        base-answer in proveded buffer 
 *
 * @retval SBCOK         The answer was successfully validated.
 * @retval SBCFAIL       Validation failed (mismatch or computation error).
 * @retval SBCNULLP      One or more input pointers are NULL.
 * @retval SBCIO         Device I/O or communication error occurred.
 * @retval SBCINVPARAM   Invalid parameter or key length.
 *
 * @note This function may internally use a cryptographic algorithm (e.g., AES, HMAC, or SHA)
 *       depending on the implementation.
 *
 * @see SBC_DeviceSecuirtyKeyCreate()
 * @see SBC_DeviceSecurityKeyVerify()
 */
//SBCStatus  SBC_BaseAnswerValidate(VOID *blkhnd, UINT8 *answer, UINTN answerl, UINT8 *key, UINTN keylen);
SBCStatus  SBC_BaseAnswerValidate(VOID *blkhnd, UINT8 *answer, UINTN answerl, UINT8 *key, UINTN keylen, BOOLEAN ischeck);
/**
 * @fn SBCStatus SBC_GenFWID(EFI_HANDLE *h_image, UINT8 *devid, UINT8 *fwid)
 * 
 * @author leoc (6/2/25)
 * 
 * @param priv    Handle for Context   
 * @param devid   Pointer to Device ID buffer where computed 
 * @param fwid    Pointer to FW ID buffer 
 * 
 * @return On Success, return the SBCOK, otherwise, return the apporiate error
 *         value.
 */
SBCStatus SBC_GenFWID(VOID *priv, UINT8 *devid, UINT8 *fwid, UINTN normbank, UINTN bm);


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

/**
 * @fn SBCStatus SBC_DeviceSecuirtyKeyCreate(VOID *key)
 * @brief Create a new device security key.
 *
 * @param[out] key   Pointer to a buffer where the generated security key
 *                   will be stored. 
 *
 * @retval SBCOK         The security key was successfully generated.
 * @retval SBCFAIL       Failed to create the security key due to internal error.
 * @retval SBCNULLP      The input pointer @p key is NULL.
 * @retval SBCIO         Hardware or I/O failure occurred during key generation.
 *
 * @see SBC_DeviceSecurityKeyLoad()
 * @see SBC_DeviceSecurityKeyVerify()
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
