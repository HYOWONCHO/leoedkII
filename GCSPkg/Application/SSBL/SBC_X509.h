/********************************************************************************
 * Copyright (C) 2024 by Security Platform Inc.                                 *
 * This file is part of the SBC Project.                                        *
 *                                                                              *
 * This software contains confidential and proprietary information of           *
 * Security Platform Inc. Unauthorized reproduction, distribution, or           *
 * disclosure of this software, in whole or in part, is strictly prohibited.    *
 ********************************************************************************/

#ifndef _SBC_X509_H
#define _SBC_X509_H


/**
 * @fn SBCStatus SBC_EcGetPublicKeyFromPem(CONST UINT8 *der, UINTN derl, VOID **ctx)
 * @brief Parse a DER-encoded EC public key and initialize an ECC context.
 *
 * @param[in]  der   Pointer to the DER-encoded public key buffer.
 * @param[in]  derl  Length of the DER-encoded data in bytes.
 * @param[out] ctx   Pointer to a variable that receives the created ECC
 *                   context handle. The context must be released using
 *                   the corresponding cleanup function when no longer needed.
 *
 * @retval SBCOK         The EC public key was successfully parsed and context created.
 * @retval SBCFAIL       Parsing failed due to malformed DER data or unsupported key type.
 * @retval SBCNULLP      One or more input pointers are NULL.
 * @retval SBCINVPARAM   Invalid parameter values or buffer length.
 * @retval SBCCRYPTO     ECC library or decoding failure occurred.
 */
SBCStatus SBC_EcGetPublicKeyFromPem(
    CONST UINT8 *der,  /**< [in] DER-encoded EC public key buffer */
    UINTN        derl, /**< [in] Length of the DER data (bytes) */
    VOID       **ctx   /**< [out] Pointer to ECC context handle */
);



/**
 * @fn SBCStatus SBC_EcGetPrivateKeyFromPem(CONST UINT8 *der,
 *                                          UINTN derl,
 *                                          CONST CHAR8 *passwd,
 *                                          VOID **ctx)
 * @brief Parse and load an EC private key from a PEM or DER encoded buffer.
 *
 * @param[in]  der      Pointer to the PEM or DER encoded EC private key buffer.
 * @param[in]  derl     Length in bytes of the @p der buffer.
 * @param[in]  passwd   Optional password string for decrypting encrypted PEM files.
 *                      Set to NULL if the key is unencrypted.
 * @param[out] ctx      Pointer to a variable that receives the loaded EC key context.
 *                      The caller must later free it using the corresponding release function.
 *
 * @retval SBCOK            Successfully parsed and loaded the EC private key.
 * @retval SBCINVPARAM      Invalid input parameter (NULL pointer or zero length).
 * @retval SBCFORMAT        Invalid key format or parse failure.
 * @retval SBCCRYPTOERR     Decryption or key material extraction failure.
 * @retval SBCMEM           Memory allocation failure.
 * @retval SBCFAIL          Unknown or internal error.
 */
SBCStatus  SBC_EcGetPrivateKeyFromPem(CONST UINT8 *der,
                                      UINTN derl,
                                      CONST CHAR8 *passwd,
                                      VOID **ctx);



/**
 * @fn SBCStatus  SBC_X509VerifyCert(CONST UINT8 *cert,
                              UINTN certl,
                              CONST UINT8 *cacert,
                              UINTN cacertl)
 * @brief Verify an X.509 certificate against a given CA certificate.
 *
 * @param[in] cert      Pointer to the certificate buffer (PEM or DER format).
 * @param[in] certl     Length in bytes of the @p cert buffer.
 * @param[in] cacert    Pointer to the CA (root or intermediate) certificate buffer (PEM or DER format).
 * @param[in] cacertl   Length in bytes of the @p cacert buffer.
 *
 * @retval SBCOK            Verification succeeded — the certificate is trusted and valid.
 * @retval SBCINVPARAM      Invalid input parameter (NULL pointer or zero length).
 * @retval SBCFORMAT        Certificate format or parsing error.
 * @retval SBCCRYPTOERR     Signature verification or chain validation failure.
 * @retval SBCEXPIRED       Certificate has expired or is not yet valid.
 * @retval SBCMEM           Memory allocation failure.
 * @retval SBCFAIL          Unknown or internal failure.
 *
 */
SBCStatus  SBC_X509VerifyCert(CONST UINT8 *cert,
                              UINTN certl,
                              CONST UINT8 *cacert,
                              UINTN cacertl);

#endif
