#include <Library/BaseCryptLib.h>
#include <Library/BaseMemoryLib.h>
#include <Library/MemoryAllocationLib.h>

#include "SBC_CryptAES.h"
#include "SBC_Log.h"


/**
 * Initialize the AES context for use
 *
 * @param[in,out] ctx       ponter to AES context being initialize
 *
 * @return On success, return the SBCOK, otherwise apporiate value
 */
SBCStatus SBC_AESInit(SBC_AESContext *ctx)
{
  if(ctx == NULL) {
    return SBCNULLP;
  }

//Print(L"AesGetCnotextSize : %d \r\n", AesGetContextSize());
//Print(L"Key Strength : %d \r\n", ctx->keylen);
//SBC_mem_print_bin("AES Key", ctx->key, SBC_KEY_LEN_128);
  ctx->handle = AllocateZeroPool(AesGetContextSize());
  if(ctx->handle == NULL) {
    return SBCNULLP;
  }

  if(AesInit(ctx->handle, ctx->key, ctx->keylen) != TRUE) {
    return SBCFAIL;
  }

  return SBCOK;
}

/**
 * AES context handle is de-inialized
 *
 * @param[in,out] ctx       ponter to AES context being initialize
 */
VOID SBC_AESDeInit(SBC_AESContext *ctx)
{
  if(ctx->handle) {
    FreePool(ctx->handle);
  }

  ctx->keylen = 0L;
}

static SBCStatus SBC_AES_CBCEncrypt(SBC_AESCBCCtx *ctx)
{

  SBCStatus ret = SBCOK;

  //DEBUG((DEBUG_INFO , "%s:%d \n",__func__, __LINE__));
  SBC_AES_RET_VAL_IF_FAIL((ctx != NULL), SBCNULLP);
  //DEBUG((DEBUG_INFO , "%s:%d \n",__func__, __LINE__));
  SBC_AES_RET_VAL_IF_FAIL((ctx->handle != NULL), SBCNULLP);
  //DEBUG((DEBUG_INFO , "%s:%d \n",__func__, __LINE__));
  SBC_AES_RET_VAL_IF_FAIL((ctx->iv != NULL), SBCNULLP);
  //DEBUG((DEBUG_INFO , "%s:%d \n",__func__, __LINE__));
  SBC_AES_RET_VAL_IF_FAIL((ctx->keylv.value != NULL), SBCNULLP);
  //DEBUG((DEBUG_INFO , "%s:%d \n",__func__, __LINE__));
  SBC_AES_RET_VAL_IF_FAIL((ctx->keylv.length != 0), SBCZEROL);
  //DEBUG((DEBUG_INFO , "%s:%d \n",__func__, __LINE__));

  Print(L"Ctx Handle : 0x%08x \r\n", ctx->handle);
  Print(L"Ctx Iv \r\n");
  SBC_mem_print_bin(NULL, ctx->iv, 16);

  Print(L"Ctx Key \r\n");
  SBC_mem_print_bin(NULL, ctx->keylv.value, SBC_KEY_LEN_128);

  Print(L"Ctx PlainText \r\n");
  SBC_mem_print_bin(NULL, ctx->inlv->value, ctx->inlv->length);


#if 1
  if(AesCbcEncrypt(ctx->handle, 
                   (CONST UINT8 *)ctx->inlv->value, 
                   ctx->inlv->length,
                   ctx->iv, 
                   ctx->outlv->value) != TRUE) {
    Print(L"AesCbcEnrypt behavior fail \r\n");
    ret = SBCENCFAIL;
    goto ErrorDone;
  }
 #endif

  ctx->outlv->length = ctx->inlv->length;



ErrorDone:

  return ret;


}


static SBCStatus SBC_AESGcmEncrypt(SBC_AESContext *ctx)
{
  SBC_AESGcmCtx *gcm = NULL;

  gcm = ctx->gcm;

  if(AeadAesGcmEncrypt(gcm->key->value, gcm->key->length,
                       gcm->iv->value, gcm->iv->length,
                       gcm->aad->value, gcm->aad->length,
                       gcm->msg->value, gcm->msg->length,
                       gcm->tag->value, gcm->tag->length,
                       gcm->out->value, &gcm->out->length)) {
    Print(L"GCM Encrypt fail \r\n");
    return SBCENCFAIL;
  }

  return SBCOK;

}

static SBCStatus SBC_AESGcmDecrypt(SBC_AESContext *ctx)
{
  SBC_AESGcmCtx *gcm = NULL;

  gcm = ctx->gcm;

  if(AeadAesGcmDecrypt(gcm->key->value, gcm->key->length,
                       gcm->iv->value, gcm->iv->length,
                       gcm->aad->value, gcm->aad->length,
                       gcm->msg->value, gcm->msg->length,
                       gcm->tag->value, gcm->tag->length,
                       gcm->out->value, &gcm->out->length)) {
    Print(L"GCM Decrypt fail \r\n");
    return SBCENCFAIL;
  }

  return SBCOK;

}



SBCStatus SBC_AESEncrypt(SBC_AESContext *ctx)
{

  SBCStatus ret = SBCOK;

  //DEBUG((DEBUG_INFO , "%s:%d \n",__func__, __LINE__));
  SBC_AES_RET_VAL_IF_FAIL((ctx != NULL), SBCNULLP);
  //DEBUG((DEBUG_INFO , "%s:%d \n",__func__, __LINE__));
  switch(ctx->algoid) {
    case SBC_CIPHER_AES_CBC:
      DEBUG((DEBUG_INFO , "%s:%d \n",__func__, __LINE__));
      SBC_AES_RET_VAL_IF_FAIL((ctx->cbc != NULL), SBCNULLP);
      //DEBUG((DEBUG_INFO , "%s:%d \n",__func__, __LINE__));

      ctx->cbc->handle = ctx->handle;
      ctx->cbc->keylv.value = ctx->key;
      ctx->cbc->keylv.length = ctx->keylen;
      ctx->cbc->iv = ctx->iv;
      ctx->cbc->inlv = ctx->in;
      ctx->cbc->outlv = ctx->out;
      ret = SBC_AES_CBCEncrypt(ctx->cbc);
      if(ret != SBCOK) {
        goto ErrorDone;
      }
      break;
    case SBC_CIPHER_AES_GCM:
      SBC_AESGcmEncrypt(ctx);
      break;
    default:
      ret = SBCINVPARAM;
      goto ErrorDone;
      break;

  }

ErrorDone:

  return ret;

}

static SBCStatus SBC_AES_CBCDecrypt(SBC_AESContext *ctx)
{
  //SBCSttaus ret = SBCOK;

  Print(L"Encrypt Message : \r\n");
  SBC_mem_print_bin(NULL, ctx->in->value, ctx->in->length);
  

  if(AesCbcDecrypt(ctx->handle, 
                   ctx->in->value, ctx->in->length,
                   ctx->iv, 
                   ctx->out->value) != TRUE) {
    DEBUG((DEBUG_INFO , "%s:%d behavio fail \n",__func__, __LINE__));
    return SBCFAIL;
  }

  ctx->out->length = ctx->in->length;

  return SBCOK;


}

SBCStatus SBC_AESDecrypt(SBC_AESContext *ctx)
{

  SBCStatus ret = SBCOK;

  //DEBUG((DEBUG_INFO , "%s:%d \n",__func__, __LINE__));
  SBC_AES_RET_VAL_IF_FAIL((ctx != NULL), SBCNULLP);
  SBC_AES_RET_VAL_IF_FAIL((ctx->handle != NULL), SBCNULLP);
  SBC_AES_RET_VAL_IF_FAIL((ctx->in != NULL), SBCNULLP);
  SBC_AES_RET_VAL_IF_FAIL((ctx->out != NULL), SBCNULLP);

  switch(ctx->algoid) {
    case SBC_CIPHER_AES_CBC:
      if((ret = SBC_AES_CBCDecrypt(ctx)) != SBCOK) {
        goto ErrorDnoe;
      }
      break;
    case SBC_CIPHER_AES_GCM:
      SBC_AESGcmDecrypt(ctx);
      break;
    default:
      ret = SBCINVPARAM;
      goto ErrorDnoe;
      break;

  }

ErrorDnoe:
  return ret;
}







