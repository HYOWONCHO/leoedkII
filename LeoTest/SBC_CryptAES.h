#ifndef _AES_CRYPT_
#define _AES_CRYPT_

#include "SBC_ErrorType.h"

typedef enum {
  SBC_CIPHER_NONE                 = 0,
  SBC_CIPHER_AES_ECB,
  SBC_CIPHER_AES_CBC,
  SBC_CIPHER_AES_CTR,
  SBC_CIPHER_AES_GCM,
  SBC_CIPHER_UNKNOWN
}SBC_CipherAlgoMode;


typedef struct {
  UINT16    tag;
  UINTN     length;
  UINT8     *value;
}SBC_CipherTLV;

typedef struct _aes_cbc_context_t {
  VOID *handle;
  SBC_CipherTLV keylv;
  SBC_CipherTLV *inlv;    /*!< Input message  */
  SBC_CipherTLV *outlv;   /*!< Output message */
  UINT8         *iv;    /*!< Pointer to initialization vector */
}SBC_AESCBCCtx;

/**
 * @struct SBC_AESGcmCtx
 * @brief AES GCM behavior context handle
 * 
 * @var  SBC_AESGcmCtx:key
 * Key regarding Encryptoin and Decectypion
 * 
 * @var SBC_AESGcmCtx:tag
 * Pointer to the buffer that receives the authentication tag
 * and size in bytes
 * 
 * @var SBC_AESGcmCtx:out
 * Poiner to a buffer that receives the encryption/decryption
 * output and size of buffer in bytes
 * 
 * @author leoc (4/25/25)
 */
typedef struct _aes_gcm_context_t {
  SBC_CipherTLV *key;     /*!< Key regarding Encryptoin and Decectypion*/
  SBC_CipherTLV *iv;      /*!< Initial vector */
  SBC_CipherTLV *aad;     /*!< Addtional authenticated data */
  SBC_CipherTLV *msg;     /*!< Message buffer pointer to encryption and decryption*/
  SBC_CipherTLV *tag;     
  SBC_CipherTLV *out;
}SBC_AESGcmCtx;


typedef struct _aes_context_t {
  VOID *handle;
  UINT8 *key;
  UINTN keylen;
  SBC_CipherAlgoMode algoid;

  SBC_CipherTLV *in;
  SBC_CipherTLV *out;
  UINT8 *iv;

  SBC_AESCBCCtx *cbc;
  SBC_AESGcmCtx *gcm;
}SBC_AESContext;

#define SBC_AES_RET_VAL_IF_FAIL(expr, val)  \
  do { if(!(expr)) {Print(L" FAILED. \r\n"); return (val);} }while (0)



#define SBC_KEY_STRENGTH_256      256
#define SBC_KEY_LEN_256           (SBC_KEY_STRENGTH_256 >> 3)

#define SBC_KEY_STRENGTH_128      128
#define SBC_KEY_LEN_128           (SBC_KEY_STRENGTH_128 >> 3)

SBCStatus SBC_AESInit(SBC_AESContext *ctx);
VOID SBC_AESDeInit(SBC_AESContext *ctx);
SBCStatus SBC_AESEncrypt(SBC_AESContext *ctxp);
SBCStatus SBC_AESDecrypt(SBC_AESContext *ctx);


#endif
