/********************************************************************************
 * Copyright (C) 2024 by Security Platform Inc.                                 *
 * This file is part of the SBC Project.                                            *
 *                                                                              *
 * This software contains confidential and proprietary information of           *
 * Security Platform Inc. Unauthorized reproduction, distribution, or           *
 * disclosure of this software, in whole or in part, is strictly prohibited.    *
 ********************************************************************************/



#ifndef __SBC_ECCSIGNVERIFY__
#define __SBC_ECCSIGNVERIFY__

#include "SBC_ErrorType.h"


#pragma pack(push, 1)
/**
 * @struct at_key_t
 * @brief Represents an ECC key pair including private and public components.
 *
 * This structure holds the private key and corresponding public key (qx, qy) used in
 * cryptographic operations such as digital signatures anzhem
 * chlrjw key exchange.
 */
typedef struct _at_key_t {
    UINT8 d[32];  /**< Private key (32 bytes for ECC-256). */

    union {
        struct {
            UINT8 qx[32];  /**< Public key X coordinate (32 bytes). */
            UINT8 qy[32];  /**< Public key Y coordinate (32 bytes). */
        } qxy;

        UINT8 value[64];   /**< Combined public key (qx || qy). */
    } q;

    UINTN dl;  /**< Length of private key in bytes. */
    UINTN ql;  /**< Length of public key in bytes. */
} at_key_t;

typedef struct _ecc_ctx_t {
    VOID *handle;
    LV_t pubkey;
    LV_t privkey;
    LV_t sharedkey;


    UINTN curveid;
}SBCEccCtx;
#pragma pack(pop)


/**
 * @fn SBC_EcCtxSetPubKey
 * @brief Sets and Inititliaze the ECC public key into the given
 *        context.
 *
 * @param[in,out] handle   Pointer to the ECC context structure.
 * @param[in]     key      Pointer to the public key data (usually 64 bytes: Qx || Qy).
 * @param[in]     keylen   Length of the public key in bytes.
 * @param[in]     curveid  Identifier for the ECC curve (e.g., NIST P-256).
 *
 */
SBCStatus SBC_EcCtxSetPubKey(VOID *handle, UINT8 *key, UINTN keylen, UINT32 curveid);

/**
 * @fn SBC_EcCtxSetPrivKey
 * @brief Sets the ECC private key into the given context.
 *
 * @param[in,out] handle   Pointer to the ECC context structure.
 * @param[in]     key      Pointer to the private key data (usually 32 bytes).
 * @param[in]     keylen   Length of the private key in bytes.
 * @param[in]     curveid  Identifier for the ECC curve (e.g., NIST P-256).
 *
 */
SBCStatus SBC_EcCtxSetPrivKey(VOID *handle, UINT8 *key, UINTN keylen, UINT32 curveid);
SBCStatus SBC_EcDsaVerify(SBCEccCtx *h, TLV_t *hash, LV_t *signature);


/*!
 * Generates ECC Key pair 
 * 
 * \author leoc (5/2/25)
 * 
 * \param[in,out] h       Pointer to ECC handle context 
 * \param curveid ECC curve realted domain parameter ID 
 * 
 * \return On success, return the SBCOK, otherwise return the apporiate value
 * 
 * \note
 *      publickey = privat key * generator point
 */
SBCStatus SBC_EccKeyGen(SBCEccCtx *h, UINTN curveid);

/**
 * @fn SBC_EcDsaVerify
 * @brief Verifies an ECDSA signature using the specified ECC context and hash.
 *
 * @param[in] h         Pointer to the ECC context containing the public key.
 * @param[in] hash      Pointer to the hash value (TLV format) that was signed.
 * @param[in] signature Pointer to the signature to verify (LV format).
 *
 * @return SBCStatus
 *         - SBCOK: Signature is valid.
 *         - SBCFAIL: Signature is invalid.
 *         - SBCNULLP: Null pointer or missing data.
 */
SBCStatus SBC_GenShareSeucrityKey(SBCEccCtx *h, UINT8 *privkey, UINTN privlen, UINT8 *pubkey, UINTN publen);


/*!
 * Create the ECDSA signature for the given input hash message
 * 
 * \author leoc (5/8/25)
 * 
 * \param[in] h         Pointer to the SBC ECC Context handle 
 * \param[in] hash      Pointer to message size and message hash to be signed      
 * \param[in,out] signature     Pointer to buffer to receive the signature
 * 
 * \return On success, return the SBCOK, otherwise, will return apporiate value
 * 
 * \note
 * In terms of "signature" arguments, when "IN", it is essential to define the size
 * of the signature buffer in bytes, while "OUT" indicates the size at the signature buffer will return.
 */
SBCStatus SBC_EcDsaSign(SBCEccCtx *h, TLV_t *hash, LV_t *signature);

/*!
 * Create the ECDSA signature for the given input hash message
 * 
 * \author leoc (5/8/25)
 * 
 * \param[in] h         Pointer to the SBC ECC Context handle 
 * \param[in] hash      Pointer to message size and message hash to be signed      
 * \param[in,out] signature     Pointer to buffer the signature to be verify
 * 
 * \return On success, return the SBCOK, otherwise, will return apporiate value
 * 
 * \note
 * In terms of "signature" arguments, when "IN", it is essential to define the size
 * of the signature buffer in bytes, while "OUT" indicates the size at the signature buffer will return.
 */
SBCStatus SBC_EcDsaVerify(SBCEccCtx *h, TLV_t *hash, LV_t *signature);


/*!
 * \brief Generate the key pair which used the DICE seed.
 * 
 * \author leoc (5/16/25)
 * 
 * \param[in] dice_seed  Pointer to the seed buffer
 * \param[out] key       Pointer to the raw key 
 * 
 * \return Returns SBCOK if succeful, otherwise returns the appropriate value for the error
 */
SBCStatus  SBC_DICESeedKeyPair(UINT8 *dice_seed, at_key_t *key);

/*!
 * Convert a raw DER-encoded key to a PEM formatted key.
 * 
 * \author leoc (5/16/25)
 * 
 * \param DerData    Pointer to the DER-encoded key.
 * \param DerSize    Size (in bytes) of the DER-encoded key.
 * \param PemHeader  PEM header string (e.g. "-----BEGIN PUBLIC KEY-----").
 * \param PemFooter  PEM footer string (e.g. "-----END PUBLIC KEY-----").
 * \param PemKey     Pointer to the allocated PEM string (caller must free).
 * \param PemKeySiz  Pointer to the size of the PEM string.
 * 
 * \retval  SBCOK  operation complete successfully
 * \retval  Others  An error occurred
 */
SBCStatus  SBC_ConvertRawKeyPem(
                                    IN  CONST UINT8  *DerData,
                                    IN  UINTN         DerSize,
                                    IN  CONST CHAR8  *PemHeader,
                                    IN  CONST CHAR8  *PemFooter,
                                    OUT CHAR8       **PemKey,
                                    OUT UINTN        *PemKeySize);
#endif
