#ifndef __SBC_ECCSIGNVERIFY__
#define __SBC_ECCSIGNVERIFY__

#include "SBC_ErrorType.h"

/*! \brief Anti-tampering key structure */
typedef struct _at_key_t {

    UINT8   d[32]; /*!< private key */
    union {
        struct {
            UINT8 qx[32];
            UINT8 qy[32];
        }qxy;
        UINT8 value[64];
    }q;

    UINTN   dl;     /*!< private key size*/
    UINTN   ql;     /*!< public key size*/
}at_key_t;


typedef struct _ecc_ctx_t {
    VOID *handle;
    LV_t pubkey;
    LV_t privkey;
    LV_t sharedkey;


    UINTN curveid;
}SBCEccCtx;


SBCStatus SBC_EcCtxSetPubKey(VOID *handle, UINT8 *key, UINTN keylen, UINT32 curveid);
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
