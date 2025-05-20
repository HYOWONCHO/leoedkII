#include <Library/BaseCryptLib.h>
#include <Library/BaseMemoryLib.h>
#include <Library/MemoryAllocationLib.h>

#include "SBC_CryptAES.h"
#include "SBC_Log.h"

#include "SBC_Util.h"
#include "SBC_Config.h"


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

////DEBUG((DEBUG_INFO , "%s:%d \n",__func__, __LINE__));
//SBC_AES_RET_VAL_IF_FAIL((ctx != NULL), SBCNULLP);
////DEBUG((DEBUG_INFO , "%s:%d \n",__func__, __LINE__));
//SBC_AES_RET_VAL_IF_FAIL((ctx->handle != NULL), SBCNULLP);
////DEBUG((DEBUG_INFO , "%s:%d \n",__func__, __LINE__));
//SBC_AES_RET_VAL_IF_FAIL((ctx->iv != NULL), SBCNULLP);
////DEBUG((DEBUG_INFO , "%s:%d \n",__func__, __LINE__));
//SBC_AES_RET_VAL_IF_FAIL((ctx->keylv.value != NULL), SBCNULLP);
////DEBUG((DEBUG_INFO , "%s:%d \n",__func__, __LINE__));
//SBC_AES_RET_VAL_IF_FAIL((ctx->keylv.length != 0), SBCZEROL);
////DEBUG((DEBUG_INFO , "%s:%d \n",__func__, __LINE__));
//
//Print(L"Ctx Handle : 0x%08x \r\n", ctx->handle);
//Print(L"Ctx Iv \r\n");
//SBC_mem_print_bin(NULL, ctx->iv, 16);
//
//Print(L"Ctx Key \r\n");
//SBC_mem_print_bin(NULL, ctx->keylv.value, SBC_KEY_LEN_128);
//
//Print(L"Ctx PlainText \r\n");
//SBC_mem_print_bin(NULL, ctx->inlv->value, ctx->inlv->length);


#if 1
  if(AesCbcEncrypt(ctx->handle, 
                   (CONST UINT8 *)ctx->inlv->value, 
                   ctx->inlv->length,
                   ctx->iv, 
                   ctx->outlv->value) != TRUE) {
    eprint("AesCbcEnrypt behavior fail \r\n");
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

//SBC_external_mem_print_bin("GCM enc key", gcm->key.value, gcm->key.length);
//SBC_external_mem_print_bin("GCM iv result", gcm->iv.value, gcm->iv.length);
////SBC_external_mem_print_bin("GCM aad result", gcm->aad.value, gcm->aad.length);
//SBC_external_mem_print_bin("GCM msg result", gcm->msg.value, gcm->msg.length);
//SBC_external_mem_print_bin("GCM tag result", gcm->tag.value, gcm->tag.length);

  if(AeadAesGcmEncrypt(gcm->key.value, gcm->key.length,
                       gcm->iv.value, gcm->iv.length,
                       gcm->aad.value, gcm->aad.length,
                       gcm->msg.value, gcm->msg.length,
                       gcm->tag.value, gcm->tag.length,
                       gcm->out.value, &gcm->out.length) == FALSE) {
    DEBUG((DEBUG_ERROR,"%a:%d GCM Encrypt fail \r\n",__FUNCTION__,__LINE__));
    return SBCENCFAIL;
  }

  //SBC_external_mem_print_bin("GCM enc result", gcm->out.value, gcm->out.length);

  return SBCOK;

}

static SBCStatus SBC_AESGcmDecrypt(SBC_AESContext *ctx)
{
  SBC_AESGcmCtx *gcm = NULL;

  gcm = ctx->gcm;

  if(AeadAesGcmDecrypt(gcm->key.value, gcm->key.length,
                       gcm->iv.value, gcm->iv.length,
                       gcm->aad.value, gcm->aad.length,
                       gcm->msg.value, gcm->msg.length,
                       gcm->tag.value, gcm->tag.length,
                       gcm->out.value, &gcm->out.length)) {
    eprint("GCM Decrypt fail \r\n");
    return SBCENCFAIL;
  }

  return SBCOK;

}



SBCStatus SBC_AESEncrypt(SBC_AESContext *ctx)
{

  SBCStatus ret = SBCOK;

  //DEBUG((DEBUG_INFO , "%s:%d \n",__func__, __LINE__));
  //SBC_AES_RET_VAL_IF_FAIL((ctx != NULL), SBCNULLP);
  //DEBUG((DEBUG_INFO , "%s:%d \n",__func__, __LINE__));
  switch(ctx->algoid) {
    case SBC_CIPHER_AES_CBC:
     // DEBUG((DEBUG_INFO , "%s:%d \n",__func__, __LINE__));
      //SBC_AES_RET_VAL_IF_FAIL((ctx->cbc != NULL), SBCNULLP);
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

  //Print(L"Encrypt Message : \r\n");
  //SBC_mem_print_bin(NULL, ctx->in->value, ctx->in->length);
  

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

#ifdef SBC_AES_UNITEST_ENABLE


#include "aes_vectortable.h"
VOID SBC_AES_TestMain(VOID)
{

  //SBCStatus ret = SBCOK;

  int testcnt = 0;
  UINT8 plaintxt[256] = {0, };
  UINT8 aesbuf[256] = {0, };
  UINT8 ivbuf[256] = {0, };
  UINT8 answer[256] = {0, };
  UINT8 keybuf[256] = {0, };
  UINT8 cmpbuf[256] = {0, };
  UINT32 convlen =0 ;

  SBC_AESCBCCtx  cbcctx;

  SBC_CipherTLV plainlv = {
    .tag = 0,
    //.length = (UINTN)strlen((unsigned char *)aesbuf),
    .length = 0,
    .value = (UINT8 *)plaintxt
  };

  SBC_CipherTLV enclv = {
    .tag = 0,
    .length = 0,
    .value = aesbuf
  };

  //UINT8 symmkey[SBC_KEY_LEN_256] = {0, };
  SBC_AESContext aesctx[26]; /* = {
    .handle = NULL,
    .key = symmkey,
    .keylen = SBC_KEY_STRENGTH_256,
    .algoid = SBC_CIPHER_NONE
  }; */
  

  
  testcnt = sizeof gt_aescbc_vector  / sizeof(SBCAESTestVectorMsg_t);
  //testcnt = 1;
  for(int x = 0; x < testcnt; x++) {

    dprint("--- %-5d ---", x);
    convlen = _convert_str_to_hex((UINT8 *)gt_aescbc_vector[x].msg , plaintxt);
    SBC_external_mem_print_bin("Plain Text", plaintxt, convlen);
    plainlv.length = convlen;
    //plainlv.value = plaintxt;
    CopyMem((VOID *)cmpbuf, (VOID *)plaintxt, convlen);
    convlen = _convert_str_to_hex((UINT8 *)gt_aescbc_vector[x].key, keybuf);
    SBC_external_mem_print_bin("Key ", keybuf, convlen);

    convlen = _convert_str_to_hex((UINT8 *)gt_aescbc_vector[x].iv, ivbuf);
    ///SBC_external_mem_print_bin("IV", ivbuf, convlen);

    convlen = _convert_str_to_hex((UINT8 *)gt_aescbc_vector[x].answer, answer);
    SBC_external_mem_print_bin("Answer", answer, convlen);

    aesctx[x].key = keybuf;
    aesctx[x].keylen  = SBC_KEY_STRENGTH_256;
    SBC_AESInit(&aesctx[x]);

    aesctx[x].cbc = &cbcctx;
    aesctx[x].key = keybuf;
    aesctx[x].keylen = SBC_KEY_STRENGTH_256 >> 3;
    aesctx[x].algoid = SBC_CIPHER_AES_CBC;
    aesctx[x].in = &plainlv;

    aesctx[x].out = &enclv;
    aesctx[x].iv = ivbuf;

    //SBC_external_mem_print_bin("Key", aesctx[x].key, aesctx[x].keylen);
    //SBC_external_mem_print_bin("IV", ivbuf, 16);

    //SBC_external_mem_print_bin("Message", aesctx[x].in->value, aesctx[x].in->length);

    if(SBC_AESEncrypt(&aesctx[x]) != SBCOK) {
      eprint("AES counter %d Encrypt fail " ,x );
      continue;
    }

    SBC_external_mem_print_bin("Encrytp", aesctx[x].out->value, aesctx[x].out->length);

    if(CompareMem((const void *)enclv.value, (const void *)answer, enclv.length) != 0 ) {
      Print(L"Counter %d Encrypt answer fail ... \n", x);
      //continue;
    }
    else {
      Print(L"Counter %d Encrypt answer ok ... \n", x);
    }

    
    aesctx[x].in = &enclv;
    aesctx[x].out = &plainlv;

    if(SBC_AESDecrypt(&aesctx[x]) != SBCOK) {
      eprint("AES decrypt fail, x");
      
      continue;
    }

    if(CompareMem((const void *)cmpbuf, (const void *)plainlv.value, plainlv.length) != 0 ) {
       Print(L"AES count %d test fail ... \n", x);
      //continue;
    }
    else{
      Print(L"AES count %d  test success ... \n", x);
    }
    SBC_external_mem_print_bin("Decrypt", aesctx[x].out->value, aesctx[x].out->length);

    SBC_AESDeInit(&aesctx[x]);
    dprint("----------------------------------------------");

  }

 

  return;
}

VOID SBC_AesGcmTestMain(VOID)
{
  SBCStatus ret = SBCOK;

  int testcnt = 0;
  UINT8 cipherbuf[256] = {0, };
  UINT8 tagbuf[256] = {0, };
  SBC_AESContext aesctx;
  SBC_AESGcmCtx  gcmctx;



  testcnt = sizeof aes_gcm_vectors  / sizeof(struct aes_gcm_vectors_st);
  //testcnt = 1;
  for(int x = 0; x < testcnt; x++) {

    dprint("--- AES GCM Test Count %d ---", x);
    gcmctx.key.value = (UINT8 *)aes_gcm_vectors[x].key;
    gcmctx.key.length = SBC_KEY_LEN_128;
    gcmctx.iv.value = (UINT8 *)aes_gcm_vectors[x].iv;
    gcmctx.iv.length = 12;
    gcmctx.aad.value = (UINT8 *)aes_gcm_vectors[x].auth;
    gcmctx.aad.length = aes_gcm_vectors[x].auth_size;
    gcmctx.msg.value = (UINT8 *)aes_gcm_vectors[x].plaintext;
    gcmctx.msg.length = aes_gcm_vectors[x].plaintext_size;
    gcmctx.tag.value = tagbuf;
    gcmctx.tag.length = 16;

    gcmctx.out.value = cipherbuf;
    gcmctx.out.length = sizeof cipherbuf;





    aesctx.gcm = &gcmctx;
    //SBC_AESInit(&aesctx[x]);

    ret = SBC_AESGcmEncrypt(&aesctx);
    if(ret != SBCOK) {
      eprint("GCM ENCRYPT FAIL \n");
      continue;
    }

    SBC_external_mem_print_bin("GCM Answer", (UINT8 *)aes_gcm_vectors[x].tag, 16);
    SBC_external_mem_print_bin("GCM TAG", gcmctx.tag.value, gcmctx.tag.length);
    if(CompareMem(gcmctx.tag.value, aes_gcm_vectors[x].tag, 16) != 0) {
      Print(L"AES GCM %d test fail \n",x);
      continue;
    }

    Print(L"AES GCM %d test success \n",x);




    //SBC_AESDeInit(&aesctx[x]);
  }
  return;
}
#endif







