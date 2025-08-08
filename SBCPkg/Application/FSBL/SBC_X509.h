#ifndef _SBC_X509_H
#define _SBC_X509_H


/*!
 * Retrive the EC public key from DER Encoded X509 certificate
 * 
 * \author leoc (5/19/25)
 * 
 * \param der    pointer to the der encoded x509 certificate
 * \param derl   Length of x509 certificate in bytes
 * \param ctx    Pointer to new-genenrate EC context 
 * 
 * \return SBCStatus 
 */
SBCStatus  SBC_EcGetPublicKeyFromPem(CONST UINT8 *der,
                                      UINTN derl,
                                      VOID **ctx);


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
