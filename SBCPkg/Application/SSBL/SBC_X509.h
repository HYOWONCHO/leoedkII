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



/*!
 * Retrive the EC private key from password-protected PEM key data
 * 
 * \author leoc (5/19/25)
 * 
 * \param der    
 * \param derl   
 * \param passwd 
 * \param ctx    
 * 
 * \return SBCStatus 
 */
SBCStatus  SBC_EcGetPrivateKeyFromPem(CONST UINT8 *der,
                                      UINTN derl,
                                      CONST CHAR8 *passwd,
                                      VOID **ctx);


/*!
 * Verify X509 certificate was issued by the trusted CA
 * 
 * \author leoc (5/19/25)
 * 
 * \param cert    
 * \param certl   
 * \param cacert  
 * \param cacertl 
 * 
 * \return SBCStatus 
 */
SBCStatus  SBC_X509VerifyCert(CONST UINT8 *cert, UINTN certl, CONST UINT8 *cacert, UINTN cacertl);
#endif
