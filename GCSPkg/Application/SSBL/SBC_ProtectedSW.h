/********************************************************************************
 * Copyright (C) 2024 by Security Platform Inc.                                 *
 * This file is part of the SBC Project.                                        *
 *                                                                              *
 * This software contains confidential and proprietary information of           *
 * Security Platform Inc. Unauthorized reproduction, distribution, or           *
 * disclosure of this software, in whole or in part, is strictly prohibited.    *
 ********************************************************************************/


#ifndef SBC_PROCTED_SW_H
#define SBC_PROCTED_SW_H

#include "SBC_ErrorType.h"
#include "SBC_TypeDefs.h"

/**
 * @def SW_PATH_STR_LEN
 * @brief Maximum string length (in bytes) for software name or version fields.
 *
 * Defines the maximum number of bytes allocated for the `name` and `ver`
 * fields in the @ref sw_path_t structure.
 */
#define SW_PATH_STR_LEN     256


#pragma pack(push, 1)
/**
 * @struct sw_path_t
 * @brief Software path and metadata descriptor.
 */

/** @var sw_path_t::name
 *  @brief Name of the software component.
 *
 *  Null-terminated ASCII string (max 256 bytes) identifying the protected
 *  software module (e.g., `"Kernel"`, `"FSBL"`, `"SecureLoader"`).
 */

/** @var sw_path_t::ver
 *  @brief Version string of the software component.
 *
 *  Null-terminated ASCII string (max 256 bytes) representing the version
 *  or build identifier (e.g., `"1.0.3"`, `"v2025-10-31"`).
 */

/** @var sw_path_t::sw_node_off
 *  @brief Offset or index of the software node.
 *
 *  Indicates the relative position or memory offset of the software image
 *  within a larger data structure or storage block.
 */

typedef struct {
    CHAR8 name[SW_PATH_STR_LEN];        /**< Software name (ASCII string). */
    CHAR8 ver[SW_PATH_STR_LEN];         /**< Software version (ASCII string). */
    CHAR8 ver2[SW_PATH_STR_LEN];         /**< Software2 version (ASCII string). */
    UINTN sw_node_off;                  /**< Software node offset or index. */
} sw_path_t;


/**
 * @struct sw_node_t
 * @brief Software node status and offset descriptor.
 */

/** @var sw_node_t::status
 *  @brief Current operational status of the software node.
 *
 *  Indicates whether the node is active, inactive, invalid, or under update.
 *  (Implementation-specific encoding, e.g., 0 = inactive, 1 = active, etc.)
 */

/** @var sw_node_t::pos
 *  @brief Logical position or index of the node in the software table.
 *
 *  Used to distinguish between multiple nodes in a protected software map.
 */

/** @var sw_node_t::sw0
 *  @brief Identifier or flag for the primary software slot (SW0).
 *
 *  Represents the first software partition or firmware image slot.
 */

/** @var sw_node_t::sw1
 *  @brief Identifier or flag for the secondary software slot (SW1).
 *
 *  Represents a backup or alternate software image slot.
 */

/** @var sw_node_t::reserved
 *  @brief Reserved for future use or alignment.
 *
 *  Typically initialized to zero.
 */

/** @var sw_node_t::sw0_off
 *  @brief Storage offset or address of the primary (SW0) image.
 *
 *  Indicates the absolute or relative offset within storage media
 *  where the SW0 image is located.
 */

/** @var sw_node_t::sw1_off
 *  @brief Storage offset or address of the secondary (SW1) image.
 *
 *  Indicates the absolute or relative offset within storage media
 *  where the SW1 image is located.
 */
typedef struct {
    UINT8  status;        /**< Software node status (active/inactive). */
    UINT8  pos;           /**< Node position index. */
    UINT8  sw0;           /**< Primary software slot identifier. */
    UINT8  sw1;           /**< Secondary software slot identifier. */
    UINT8  reserved[12];  /**< Reserved (alignment or future use). */
    UINTN  sw0_off;       /**< Offset of primary (SW0) image. */
    UINTN  sw1_off;       /**< Offset of secondary (SW1) image. */
} sw_node_t;
#pragma pack(pop)
/**
 * @enum AT_RP_SW_NODE_SLOT_T
 * @brief Enumeration for software node slot identifiers.
 */

/** @var AT_RP_SW_NODE_SLOT0
 *  @brief Primary software slot (SW0).
 *
 *  Represents the default or active software image region.
 */
 
/** @var AT_RP_SW_NODE_SLOT1
 *  @brief Secondary software slot (SW1).
 *
 *  Represents the backup or alternate software image region.
 */
typedef enum {
    AT_RP_SW_NODE_SLOT0 = 0,  /**< Primary slot (SW0). */
    AT_RP_SW_NODE_SLOT1 = 1,  /**< Secondary slot (SW1). */
} AT_RP_SW_NODE_SLOT_T;


/**
 * @def SBC_AT_RP_SW_NAME_MAX
 * @brief Maximum length (in bytes) for a protected software name.
 *
 * Defines the maximum size allocated for a software name string in
 * the protected software (SW) profile or path table.
 */
#define SBC_AT_RP_SW_NAME_MAX           256

/**
 * @def SBC_AT_RP_SYS_CONF_MAX_LEN
 * @brief Maximum system configuration data length (in bytes).
 *
 * Defines the upper limit for the size of system configuration data
 * stored in the SBC raw partition.
 */
#define SBC_AT_RP_SYS_CONF_MAX_LEN      (16 * 1024)

/**
 * @def SBC_AT_RP_PROFILE_MAX_LEN
 * @brief Maximum profile data length (in bytes).
 *
 * Specifies the maximum size of the SBC software profile table,
 * which includes SW path, version, and status information.
 */
#define SBC_AT_RP_PROFILE_MAX_LEN       4096

/**
 * @def SBC_AT_RP_SW_BLOCK_LEN
 * @brief Default software block length (in bytes).
 *
 * Represents the standard block size used when reading or writing
 * protected software data from the partition.
 */
#define SBC_AT_RP_SW_BLOCK_LEN          1024

/**
 * @def SBC_AT_RP_SW_PATH_MAX
 * @brief Maximum number of software path entries in the profile table.
 *
 * Defines the number of @ref sw_path_t entries that can fit within
 * a 16 KB partition region.
 *
 * @note
 * Calculated approximately as `16K / sizeof(sw_path_t)` = 58.
 */
#define SBC_AT_RP_SW_PATH_MAX           58  /**< 16K / sizeof(sw_path_t) */

/**
 * @def SBC_AT_RP_CERT_MAX_LEN
 * @brief Maximum certificate length (in bytes).
 *
 * Specifies the upper size limit for a software or system certificate
 * stored within the SBC raw partition.
 */
#define SBC_AT_RP_CERT_MAX_LEN          (2 * 1024)

/**
 * @def SBC_AT_RP_AAD_LENGTH
 * @brief Additional Authenticated Data (AAD) length (in bytes).
 *
 * Defines the fixed length of AAD used during AES-GCM encryption or
 * decryption operations for integrity protection.
 */
#define SBC_AT_RP_AAD_LENGTH            20

/**
 * @def SBC_AT_RP_TAG_LEN
 * @brief AES-GCM authentication tag length (in bytes).
 *
 * Defines the size of the authentication tag appended to each
 * encrypted message to verify its integrity.
 */
#define SBC_AT_RP_TAG_LEN               16

/**
 * @def SBC_AT_RP_IV_LEN
 * @brief AES-GCM initialization vector (IV) length (in bytes).
 *
 * Specifies the standard IV size (12 bytes) recommended for
 * AES-GCM cryptographic operations.
 */
#define SBC_AT_RP_IV_LEN                12

/**
 * @def SBC_AT_RP_KEY_LEN
 * @brief AES key length (in bytes).
 *
 * Defines the key size (32 bytes = 256 bits) used in AES-256 encryption.
 */
#define SBC_AT_RP_KEY_LEN               32

/**
 * @def SBC_AT_RP_RES_LEN
 * @brief Reserved field length (in bytes).
 *
 * Defines the number of bytes reserved for future expansion or
 * alignment in partition-related structures.
 */
#define SBC_AT_RP_RES_LEN               16


/**
 * @fn SBCStatus SBC_ProtSWGetCnt(VOID *handle, UINTN *cnt)
 * @brief Retrieve the number of protected software entries.
 *
 * @param[in]  handle   Pointer to the SBC protected software handle or context.
 *                      This handle references the initialized partition or
 *                      data structure containing software metadata.
 * @param[out] cnt      Pointer to a variable that receives the number of
 *                      registered software entries.
 *
 * @retval SBCOK         The count was successfully retrieved.
 * @retval SBCFAIL       Failed to read software information or count.
 * @retval SBCNULLP      One or more input pointers are NULL.
 * @retval SBCINVPARAM   Invalid handle or uninitialized software context.
 * @retval SBCIO         I/O or storage access error occurred.
 */
SBCStatus SBC_ProtSWGetCnt(VOID *handle, UINTN *cnt);


/**
 * @fn SBCStatus SBC_ProtSWReCrypto(
 *   VOID  *handle,  
 *   UINT8 *key,      
 *   UINT8 *migkey,   
 *   UINT8 *decbuf,   
 *   UINT32 *declen   
 *   )
 *
 * @brief Decrypt a protected software (SW) image or data block.
 *
 * @param[in]  handle   Pointer to the SBC protected software context or partition handle.
 *                      Used to identify which protected SW data is being decrypted.
 * @param[in]  key      Pointer to the decryption key (typically 256-bit AES key).
 *                      Must be a valid key of length @ref SBC_AT_RP_KEY_LEN bytes.
 * @param[in]  migkey   Pointer to the migration key, used for key-rotation or
 *                      re-encryption operations. May be NULL if not applicable.
 * @param[out] decbuf   Pointer to a caller-allocated buffer that receives the
 *                      decrypted data. The buffer must be large enough to hold
 *                      the plaintext output.
 * @param[in,out] declen Pointer to a variable that specifies the size of @p decbuf (input)
 *                      and receives the actual length of decrypted data (output).
 *
 * @retval SBCOK         Decryption completed successfully.
 * @retval SBCFAIL       Decryption failed due to invalid key or corrupted data.
 * @retval SBCNULLP      One or more input pointers are NULL.
 * @retval SBCINVPARAM   Invalid parameter (e.g., incorrect buffer length or key).
 * @retval SBCCRYPTO     Cryptographic engine or AES-GCM error.
 */
SBCStatus SBC_ProtSWReCrypto(
    VOID  *handle,   /**< [in] Protected SW context handle */
    UINT8 *key,      /**< [in] Decryption key (AES-256) */
    UINT8 *migkey,   /**< [in] Optional migration key */
    UINT8 *decbuf,   /**< [out] Decrypted data buffer */
    UINT32 *declen   /**< [in,out] Buffer length / decrypted size */
);

/**
 * @fn SBCStatus SBC_RecryptoProtectedSW(VOID *handle, UINTN ofs, UINT8 *sw_secret_key, UINT8 *sw_mig_key)
 * @brief Re-encrypt (re-crypto) a protected software image using a new key set.
 *
 * @param[in] handle          Pointer to the SBC protected software context or partition handle.
 *                            Identifies the target partition containing the software data.
 * @param[in] ofs             Offset or index of the software block to re-encrypt.
 *                            Typically corresponds to the node offset within the partition.
 * @param[in] sw_secret_key   Pointer to the main AES key (e.g., 256-bit key) used for re-encryption.
 *                            Must be @ref SBC_AT_RP_KEY_LEN bytes long.
 * @param[in] sw_mig_key      Pointer to the migration key used for transitioning
 *                            to a new key version or hierarchy.  
 *                            May be @c NULL if only a single key is used.
 *
 * @retval SBCOK         Re-encryption successfully completed.
 * @retval SBCFAIL       Re-encryption failed due to data corruption or key mismatch.
 * @retval SBCNULLP      One or more input pointers are NULL.
 * @retval SBCINVPARAM   Invalid offset, key length, or partition context.
 * @retval SBCCRYPTO     Cryptographic engine or AES-GCM processing error.
 * @retval SBCIO         I/O failure during read or write to the secure partition.
 */
SBCStatus SBC_RecryptoProtectedSW(
    VOID  *handle,         /**< [in] Protected software partition handle */
    UINTN  ofs,            /**< [in] Offset of the software node to re-encrypt */
    UINT8 *sw_secret_key,  /**< [in] Primary software encryption key (AES-256) */
    UINT8 *sw_mig_key      /**< [in] Migration key for key rotation (optional) */
);


/**
 * @fn SBCStatus SBC_ReadProtectedSwSlotOffset(VOID *handle, UINTN *check, CHAR8 *sw_name, UINTN slot, UINTN *offset)
 * @brief Retrieve the storage offset of a specific protected software slot (SW0/SW1).
 *
 * @param[in]  handle   Pointer to the SBC protected software context or partition handle.
 *                      Identifies the initialized software list or raw partition.
 * @param[out] check    Pointer to a variable used for validation or integrity checking.
 *                      This may indicate whether the software entry or offset is valid.
 * @param[in]  sw_name  ASCII string representing the software name to locate.
 *                      (e.g., `"SecureOS"`, `"Loader"`, `"FSBL"`).
 * @param[in]  slot     Slot index to read (e.g., 0 = SW0, 1 = SW1).  
 *                      See @ref AT_RP_SW_NODE_SLOT_T for slot definitions.
 * @param[out] offset   Pointer to a variable that receives the slot’s storage offset value.
 *
 * @retval SBCOK         The software slot offset was successfully read.
 * @retval SBCFAIL       Failed to find the specified software entry or read offset.
 * @retval SBCNULLP      One or more input pointers are NULL.
 * @retval SBCINVPARAM   Invalid slot index or software name.
 * @retval SBCIO         Storage access or partition read failure.
 */
SBCStatus SBC_ReadProtectedSwSlotOffset(
    VOID  *handle,   /**< [in] Protected software context handle */
    UINTN *check,    /**< [out] Integrity or validation flag pointer */
    CHAR8 *sw_name,  /**< [in] Software name to locate */
    UINTN  slot,     /**< [in] Slot index (0 = SW0, 1 = SW1) */
    UINTN *offset    /**< [out] Slot offset value */
);

/**
 * @fn SBCStatus SBC_LoadSysFile(VOID *handle, UINTN offset, UINT8 *deckey, UINT8 *data)
 * @brief Load and decrypt a protected system file from the secure partition.
 *
 * @param[in]  handle   Pointer to the SBC protected system or partition context.
 *                      Identifies the initialized secure storage interface.
 * @param[in]  offset   Offset (in bytes or blocks) within the secure partition
 *                      where the target system file is located.
 * @param[in]  deckey   Pointer to the decryption key used to decrypt the file.
 *                      Must be a valid AES key (e.g., 256 bits = @ref SBC_AT_RP_KEY_LEN bytes).
 * @param[out] data     Pointer to a caller-allocated buffer that receives the
 *                      decrypted file contents.
 *
 * @retval SBCOK         File successfully loaded and decrypted.
 * @retval SBCFAIL       Decryption or file read operation failed.
 * @retval SBCNULLP      One or more input pointers are NULL.
 * @retval SBCINVPARAM   Invalid offset or buffer parameters.
 * @retval SBCCRYPTO     AES decryption or authentication tag verification failed.
 * @retval SBCIO         I/O or partition read failure.
 */
SBCStatus SBC_LoadSysFile(
    VOID  *handle,   /**< [in] Protected system or partition context handle */
    UINTN  offset,   /**< [in] Offset of the target system file */
    UINT8 *deckey,   /**< [in] Decryption key (AES-256) */
    UINT8 *data      /**< [out] Buffer to receive decrypted file contents */
);




//
//SBCStatus SBC_UpdateProtectedSWListVersion(VOID *handle, CHAR8 *sw_name, CHAR8 *sw_ver);
//
//SBCStatus SBC_UpdateProtecteSWSlotInfo(VOID *handle, CHAR8 *sw_name);
//
//SBCStatus SBC_FindProtectedSw(VOID *handle, CHAR8 name[256], CHAR8 *ver, UINTN *sw_node_off);
//
//SBCStatus SBC_WriteProtSwNodeBlob(VOID *handle, UINTN swoff, UINT8 *blob, UINTN blob_len, UINT8 *iv, UINT8 *tag);
//
//SBCStatus SBC_WriteProtSwSize(VOID *handle, UINTN sw_off, UINTN size);
//
//SBCStatus SBC_GetProtectedSwName(VOID *handle, UINTN st, CHAR8 *sw_name, UINTN sw_name_size);
//
#endif

