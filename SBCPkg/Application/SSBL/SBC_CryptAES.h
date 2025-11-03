/********************************************************************************
 * Copyright (C) 2024 by Security Platform Inc.                                 *
 * This file is part of the SBC Project.                                        *
 *                                                                              *
 * This software contains confidential and proprietary information of           *
 * Security Platform Inc. Unauthorized reproduction, distribution, or           *
 * disclosure of this software, in whole or in part, is strictly prohibited.    *
 ********************************************************************************/

#ifndef _AES_CRYPT_
#define _AES_CRYPT_

#include "SBC_ErrorType.h"

/**
 * @enum SBC_CipherAlgoMode
 * @brief Defines supported cipher algorithm modes used in the SBC cryptographic framework.
 *
 * This enumeration specifies the available cipher modes for encryption and decryption operations.
 */
typedef enum {
  SBC_CIPHER_NONE       = 0,  /**< No cipher algorithm selected. */
  SBC_CIPHER_AES_ECB,         /**< AES in Electronic Codebook (ECB) mode. */
  SBC_CIPHER_AES_CBC,         /**< AES in Cipher Block Chaining (CBC) mode. */
  SBC_CIPHER_AES_CTR,         /**< AES in Counter (CTR) mode. */
  SBC_CIPHER_AES_GCM,         /**< AES in Galois/Counter Mode (GCM) for authenticated encryption. */
  SBC_CIPHER_UNKNOWN          /**< Unknown or unsupported cipher mode. */
} SBC_CipherAlgoMode;


/**
 * @struct SBC_CipherTLV
 * @brief Represents a generic TLV (Tag-Length-Value) structure used in cipher operations.
 *  
 * This structure is used to encapsulate cryptographic data such as keys, input messages,
 * or output buffers in a flexible TLV format.
 */
typedef struct {
  UINT16    tag;     /**< Identifier tag for the data type. */
  UINTN     length;  /**< Length of the value in bytes. */
  UINT8     *value;  /**< Pointer to the actual data value. */
} SBC_CipherTLV;

/**
 * @struct SBC_AESCBCCtx
 * @brief AES-CBC encryption/decryption context structure.
 *
 * This structure holds the necessary parameters for performing AES-CBC operations,
 * including the key, input/output buffers, and initialization vector.
 */
typedef struct _aes_cbc_context_t {
  VOID *handle;             /**< Internal handle or context reference. */
  SBC_CipherTLV keylv;      /**< Key data in TLV format. */
  SBC_CipherTLV *inlv;      /**< Pointer to input message TLV. */
  SBC_CipherTLV *outlv;     /**< Pointer to output message TLV. */
  UINT8 *iv;                /**< Pointer to the initialization vector (IV). */
} SBC_AESCBCCtx;

/**
 * @struct SBC_AESGcmCtx
 * @brief AES-GCM operation context structure.
 *
 * This structure defines all necessary parameters for performing AES-GCM
 * encryption and decryption operations, including key, IV, AAD, message,
 * authentication tag, and output buffer.
 *
 * It provides a unified data container for passing cryptographic
 * parameters to AES-GCM APIs.
 *
 * @author leoc
 * @date 2025-04-25
 */

/** @var SBC_AESGcmCtx::key
 *  @brief Key used for encryption and decryption.
 *
 *  Contains the symmetric AES key and its size information.
 */

/** @var SBC_AESGcmCtx::iv
 *  @brief Initialization Vector (IV) for AES-GCM operation.
 *
 *  A unique nonce required for each encryption to ensure data security.
 */

/** @var SBC_AESGcmCtx::aad
 *  @brief Additional Authenticated Data (AAD).
 *
 *  Data that is authenticated but not encrypted, typically used for
 *  protocol headers or integrity metadata.
 */

/** @var SBC_AESGcmCtx::msg
 *  @brief Message buffer used for encryption or decryption.
 *
 *  Contains the plaintext input (for encryption) or ciphertext input
 *  (for decryption), along with its length.
 */

/** @var SBC_AESGcmCtx::tag
 *  @brief Authentication tag buffer and its size.
 *
 *  Receives the 16-byte authentication tag (for encryption)
 *  or provides it (for decryption) to verify message integrity.
 */

/** @var SBC_AESGcmCtx::out
 *  @brief Output buffer for AES-GCM operation.
 *
 *  Holds the resulting ciphertext (for encryption) or plaintext
 *  (for decryption) and its size in bytes.
 */
typedef struct _aes_gcm_context_t {
    SBC_CipherTLV key;   /*!< AES key for encryption and decryption. */
    SBC_CipherTLV iv;    /*!< Initialization vector (IV). */
    SBC_CipherTLV aad;   /*!< Additional authenticated data (AAD). */
    SBC_CipherTLV msg;   /*!< Message buffer (plaintext/ciphertext). */
    SBC_CipherTLV tag;   /*!< Authentication tag (16 bytes typical). */
    SBC_CipherTLV out;   /*!< Output buffer for processed data. */
} SBC_AESGcmCtx;


/**
 * @struct SBC_AESContext
 * @brief Represents a unified context for AES encryption and decryption operations.
 *
 * This structure encapsulates all necessary parameters and sub-contexts required to perform
 * AES-based cryptographic operations. It supports multiple cipher modes including CBC and GCM.
 *
 * @note
 * Depending on the selected algorithm mode (`algoid`), either the CBC or GCM sub-context
 * will be used during encryption or decryption.
 */
typedef struct _aes_context_t {
  VOID *handle;                 /**< Internal handle or reference for context management. */
  UINT8 *key;                   /**< Pointer to the AES key. */
  UINTN keylen;                 /**< Length of the AES key in bytes. */
  SBC_CipherAlgoMode algoid;    /**< Cipher algorithm mode (e.g., CBC, GCM). */

  SBC_CipherTLV *in;            /**< Pointer to input data in TLV format. */
  SBC_CipherTLV *out;           /**< Pointer to output buffer in TLV format. */
  UINT8 *iv;                    /**< Initialization vector used for CBC or GCM modes. */

  SBC_AESCBCCtx *cbc;           /**< AES-CBC mode context. Used when algoid is SBC_CIPHER_AES_CBC. */
  SBC_AESGcmCtx *gcm;           /**< AES-GCM mode context. Used when algoid is SBC_CIPHER_AES_GCM. */
} SBC_AESContext;

/**
 * @def SBC_AES_KEY_STRENGTH
 * @brief AES key length in bytes (256-bit key).
 */
#define SBC_AES_KEY_STRENGTH          32  /**< 256-bit AES key (32 bytes). */

/**
 * @def SBC_AES_IV_STRENGTH
 * @brief AES initialization vector (IV) length in bytes for GCM mode.
 */
#define SBC_AES_IV_STRENGTH           12  /**< 96-bit IV (12 bytes), recommended for AES-GCM. */

/**
 * @def SBC_AES_TAG_STRENGTH
 * @brief AES-GCM authentication tag length in bytes.
 */
#define SBC_AES_TAG_STRENGTH          16  /**< 128-bit authentication tag (16 bytes). */

/**
 * @def SBC_KEY_STRENGTH_256
 * @brief AES key strength in bits (256-bit).
 */
#define SBC_KEY_STRENGTH_256          256  /**< AES key strength: 256 bits. */

/**
 * @def SBC_KEY_LEN_256
 * @brief AES key length in bytes for 256-bit key.
 */
#define SBC_KEY_LEN_256               (SBC_KEY_STRENGTH_256 >> 3)  /**< 32 bytes (256 bits). */

/**
 * @def SBC_KEY_STRENGTH_128
 * @brief AES key strength in bits (128-bit).
 */
#define SBC_KEY_STRENGTH_128          128  /**< AES key strength: 128 bits. */

/**
 * @def SBC_KEY_LEN_128
 * @brief AES key length in bytes for 128-bit key.
 */
#define SBC_KEY_LEN_128               (SBC_KEY_STRENGTH_128 >> 3)  /**< 16 bytes (128 bits). */



/**
 * @fn SBC_AESInit
 * @brief Initializes the AES encryption context with the provided key.
 *
 * @param[in,out] ctx Pointer to the AES context structure to be initialized.
 *
 * @return SBCStatus
 *         - SBCOK: Initialization succeeded.
 *         - SBCNULLP: Null pointer or memory allocation failure.
 *         - SBCFAIL: AES initialization failed.
 */
SBCStatus SBC_AESInit(SBC_AESContext *ctx);

/**
 * @fn SBC_AESDeInit
 * @brief DeInitializes the AES encryption context 
 *
 * @param[in,out] ctx Pointer to the AES context structure to be
 *       de-initialized.
 *
 * @return SBCStatus
 *         - SBCOK: Initialization succeeded.
 *         - SBCFAIL: AES De-initialization failed.
 */
VOID SBC_AESDeInit(SBC_AESContext *ctx);

/**
 * @fn SBC_AESEncrypt
 * @brief Performs AES encryption using the specified context
 *        and cipher mode 
 * 
 * @author leonc (10/31/25)
 * 
 * @param ctxp   Pointer to the AES context structure containing
 *               encryption parameters
 * 
 * @return SBCStatus
 *         - SBCOK: Initialization succeeded.
 *         - SBCFAIL: AES Encryption failed.
 */
SBCStatus SBC_AESEncrypt(SBC_AESContext *ctxp);

/**
 * @fn SBC_AESDecrypt
 * @brief Performs AES decryption using the specified context
 *        and cipher mode 
 * 
 * @author leonc (10/31/25)
 * 
 * @param ctxp   Pointer to the AES context structure containing
 *               decrypt parameters
 * 
 * @return SBCStatus
 *         - SBCOK: Initialization succeeded.
 *         - SBCFAIL: AES Decryption failed.
 */
SBCStatus SBC_AESDecrypt(SBC_AESContext *ctx);


/**
 * @fn SBC_AESGcmDecrypt
 * @brief Performs AES GCM decryption using the specified
 *        context and cipher mode
 * 
 * @author leonc (10/31/25)
 * 
 * @param ctxp   Pointer to the AES GCM context structure
 *               containing decrypt parameters
 * 
 * @return SBCStatus
 *         - SBCOK: Initialization succeeded.
 *         - SBCFAIL: Decryption failed.
 */
SBCStatus SBC_AESGcmDecrypt(SBC_AESContext *ctx);


/**
 * @fn SBC_AESEncrypt
 * @brief Performs AES GCM decryption using the specified
 *        context and cipher mode
 * 
 * @author leonc (10/31/25)
 * 
 * @param ctxp   Pointer to the AES GCM context structure
 *               containing decryption parameters
 * 
 * @return SBCStatus
 *         - SBCOK: Initialization succeeded.
 *         - SBCFAIL: Encryption failed.
 */
SBCStatus SBC_AESGcmEncrypt(SBC_AESContext *ctx);

/**
 * @fn SBC_AESGcmSetContext
 * @brief Initializes the AES-GCM context with key, IV, and authentication tag.
 *
 * This function sets up the `SBC_AESGcmCtx` structure with the provided key, initialization vector (IV),
 * and authentication tag. It also clears the AAD (Additional Authenticated Data) field by default.
 *
 * @param[in,out] ctx   Pointer to the AES-GCM context structure to be initialized.
 * @param[in]     key   Pointer to the AES key (must be 256 bits / 32 bytes).
 * @param[in]     iv    Pointer to the initialization vector (must be 96 bits / 12 bytes).
 * @param[in]     tag   Pointer to the authentication tag buffer (must be 128 bits / 16 bytes).
 *
 * @note
 * This function does not perform any encryption or decryption. It only prepares the context
 * for subsequent AES-GCM operations.
 *
 * @warning
 * The caller must ensure that the provided pointers (`ctx`, `key`, `iv`, `tag`) are valid
 * and point to memory regions of appropriate size.
 */
void SBC_AESGcmSetContext(VOID *ctx, VOID *key, VOID *iv, VOID *tag);
#endif
