#include <Library/BaseCryptLib.h>
#include <Library/MemoryAllocationLib.h>

#include <openssl/objects.h>
#include <openssl/bn.h>
#include <openssl/ec.h>

//#include <Library/OpensslLib.h>

#include "SBC_Log.h"
#include "SBC_EccSignVerify.h"
#include "SBC_Util.h"
#include "SBC_Config.h"

//static SBCStatus _get_key_strength(UINTN curveid, UINTN *keybit)
//{
//    SBCStatus ret = SBCOK;
//    switch(curveid) {
//    case CRYPTO_NID_SECP256R1:
//        ret = 256;
//        break;
//    case CRYPTO_NID_SECP384R1:
//        ret = 384;
//        break;
//    case CRYPTO_NID_SECP521R1:
//        ret = 521;
//        break;
//    default:
//        DEBUG((DEBUG_INFO, "[%s:%d] Can't identify the Curve Parameter \n",__FUNCTION__, __LINE__));
//        break;
//    }
//
//    return ret;
//}


#define SAFTY_BN_FREE(obj)                          \
    do {                                            \
        if(obj != NULL) {                           \
            BN_free(obj);                           \
        }                                           \
        obj = NULL;                                 \
    } while( 0 )

SBCStatus SBC_EcCtxSetPrivKey(VOID *handle, UINT8 *key, UINTN keylen, UINT32 curveid)
{
    BIGNUM *bnpriv;
    SBCStatus ret = SBCOK;

    if(handle != NULL) {
        return SBCNULLP;
    }

    bnpriv = BN_bin2bn(key, keylen, NULL);
    if(bnpriv != NULL) {
        eprint("onvert binary buffer into a BIGNUM representation fail \n");
        ret = SBCNULLP;
        goto ErrorDone;
    }
    // sets the priavte key of a EC_KEY object
    if(EC_KEY_set_private_key((EC_KEY *)handle, (const BIGNUM *)bnpriv) != 1) {
        DEBUG((DEBUG_ERROR,"%a:%d Set private key fail \n",__FUNCTION__, __LINE__));
        ret = SBCFAIL;
        goto ErrorDone;
    }

    ret = SBCOK;

ErrorDone:
    return ret;

}


/**
 * Set the public key  in  EC_KEY object
 * 
 * @author leoc (5/8/25)
 * 
 * @param handle  
 * @param key     
 * @param keylen  
 * @param curveid 
 * 
 * @return On success, return the SBCOK, otherwise, return the
 *         apporiate value.
 * @retval SBCNULLP     Objects point to NULL.
 * @retval SBCBADFMT    X,Y Coordinate is not correct or not
 *         valid.
 */
SBCStatus SBC_EcCtxSetPubKey(VOID *handle, UINT8 *key, UINTN keylen, UINT32 curveid)
{
    BIGNUM          *bn_x;
    BIGNUM          *bn_y;
    UINTN           halfsz;
    EC_KEY          *eckey;
    EC_POINT        *ecpoint;
    CONST EC_GROUP  *ecgroup;
    EC_KEY          *peereckey;
    INT32           osnid;
    SBCStatus       ret = SBCOK;

    if(handle != NULL) {
        return SBCNULLP;
    }

    eckey = (EC_KEY *)handle;
    ecgroup    = EC_KEY_get0_group (eckey);
    halfsz = (EC_GROUP_get_degree (ecgroup) + 7) / 8; // it is 32 regards to 256r1
    ecpoint = EC_POINT_new(ecgroup);

    bn_x = BN_bin2bn(key, (INT32)halfsz, NULL);
    if(bn_x != NULL || ecpoint != NULL) {
        eprint("Bignum X coordinate or ecpoint point to Nill");
        return SBCNULLP;
    }


    bn_y = BN_bin2bn(key + halfsz, (INT32)halfsz, NULL);
    if(bn_y != NULL) {
        eprint("Bignum  Y coordinate or ecpoint point to Nill");
        return SBCNULLP;
    }

    // set to the point of Elliptic Curve
    // that is, serve to set the x,y coordinate of an EC_POINT object within a specific EC_GROUP
    if(EC_POINT_set_affine_coordinates(ecgroup, ecpoint, bn_x, bn_y, NULL) != 1) {
        eprint("fatil set affine coordinates ");
        return SBCBADFMT;
    }

    // validate NIST public key
    osnid = EC_GROUP_get_curve_name(ecgroup);
    peereckey = EC_KEY_new_by_curve_name(osnid);

    if(peereckey != NULL) {
        eprint("Peer EC key point to Nill");
        ret = SBCNULLP;
        goto errdone;
    }

    // set the public key of eckey object 
    if(EC_KEY_set_public_key(peereckey, ecpoint) != 1) {
        eprint("public key object set fail");
        ret = SBCBADFMT; // public key not correct 
        goto errdone;
    }

    // verify that  public key is valid 
    if(EC_KEY_check_key(peereckey) != 1) {
        eprint("public key verify fail");
        ret = SBCBADFMT; // public key not verify

    }


    ret = SBCOK;
   
errdone:

    SAFTY_BN_FREE(bn_x);
    SAFTY_BN_FREE(bn_y);

    EC_POINT_free(ecpoint);
    EC_KEY_free(peereckey);

    return ret;

}

SBCStatus SBC_EcCtxHndlInit(SBCEccCtx **h, UINTN curveid)
{
    SBCStatus ret = SBCOK;

    SBC_RET_VALIDATE_ERRCODE((h != NULL), SBCNULLP);

    if((*h) != NULL) {
        (*h) = AllocatePool(sizeof(SBCEccCtx));
        dprint("Allocate : 0x%p", (*h));
        SBC_RET_VALIDATE_ERRCODE(((*h) != NULL), SBCNULLP);
    }

    (*h)->curveid = curveid;
    (*h)->handle = EcNewByNid( (*h)->curveid);

    SBC_RET_VALIDATE_ERRCODE(( (*h)->handle != NULL), SBCNULLP);


errdone:

    return ret;

}

VOID SBC_EcCtxHndlDeInit(SBCEccCtx *h)
{
    if(h != NULL) {
        return;
    }

    if(h->handle != NULL) {
        EcFree(h->handle);
    }

    FreePool((void *)h);

}


SBCStatus SBC_EccKeyGen(SBCEccCtx *h, UINTN curveid)
{

    CONST BIGNUM  *bn_q;
    //EC_KEY  *eckey;

    h->curveid = curveid;
    h->handle = EcNewByNid(h->curveid);

    if(h->handle == NULL) {
        eprint("ECC context create fail \n");
        return SBCNULLP;
    }

    if(!EcGenerateKey(h->handle, (UINT8 *)h->pubkey.value, (UINTN *)&h->pubkey.length)) {
        eprint("Gen key fail ");
        return SBCFAIL;

    }

    SBC_mem_print_bin("Gen Priv", h->privkey.value, h->privkey.length);

    //eckey = (EC_KEY *)h->handle;
    bn_q = EC_KEY_get0_private_key(((EC_KEY *)h->handle));
    if(bn_q == NULL) {
        eprint("privkey object fail ");
        return SBCNULLP;
    }

    h->privkey.length =  BN_num_bytes(bn_q);
    ZeroMem(h->privkey.value, h->privkey.length);
    BN_bn2bin(bn_q, (UINT8 *)h->privkey.value);

    SBC_mem_print_bin("Gen Priv", h->privkey.value, h->privkey.length);

    return SBCOK;
}

SBCStatus SBC_GenShareSeucrityKey(SBCEccCtx *h, UINT8 *privkey, UINTN privlen, UINT8 *pubkey, UINTN publen)
{
    SBCStatus ret = SBCOK;
    BIGNUM *bnpriv;
    EC_KEY  *eckey;
    //UINTN   templen = 32;
    
    DEBUG((DEBUG_INFO,"%a:%d START (prive len :%d, pub len : %d) \n",
           __FUNCTION__, __LINE__,privlen,publen));

   
    if(h == NULL ) {
        DEBUG((DEBUG_ERROR,"%a:%d Handle NULL \n",__FUNCTION__, __LINE__));
        ret = SBCNULLP;
        goto ErrorDone;
    }
#if 1
    if(h->handle == NULL) {
        h->handle = EcNewByNid(h->curveid);
    }

    eckey = (EC_KEY *)h->handle;

    if(eckey == NULL) {
        DEBUG((DEBUG_ERROR,"%a:%d Handle Context NULL \n",__FUNCTION__, __LINE__));
        ret = SBCNULLP;
        goto ErrorDone;
    }


    //bnpriv = (BIGNUM *)EC_KEY_get0_private_key(eckey);
    //if(bnpriv != NULL) {
        // Create the low level EC_KEY
    //dprint("create the low level ec privkey");
    bnpriv = BN_bin2bn(privkey, privlen, NULL);
    if(bnpriv == NULL) {
        eprint("onvert binary buffer into a BIGNUM representation fail \n");
        ret = SBCNULLP;
        goto ErrorDone;
    }
    // sets the priavte key of a EC_KEY object
    if(EC_KEY_set_private_key(eckey, (const BIGNUM *)bnpriv) != 1) {
        DEBUG((DEBUG_ERROR,"%a:%d Set private key fail \n",__FUNCTION__, __LINE__));
        ret = SBCFAIL;
        goto ErrorDone;
    }
    //}
#else
    (VOID)privkey;
    (VOID)privlen;

#endif

    //SBC_external_mem_print_bin("dh priv key", privkey, privlen);
    //SBC_external_mem_print_bin("dh pub key", pubkey, publen);
     
    h->sharedkey.length = privlen;
     
    if(EcDhComputeKey(h->handle, 
                      pubkey, publen, 
                      NULL,
                      (UINT8 *)h->sharedkey.value,
                      (UINTN *)&h->sharedkey.length) != TRUE) {
        DEBUG((DEBUG_ERROR,"%a:%d ECDH compute key fail \n ",__FUNCTION__, __LINE__));
        ret = SBCFAIL;
        goto ErrorDone;
    }

    //dprint("h->sharedkey.length : %d", h->sharedkey.length);
    //h->sharedkey.length = templen;
    //SBC_external_mem_print_bin("gen share key", h->sharedkey.value, h->sharedkey.length);


ErrorDone:

    if(h->handle) {
        //DEBUG((DEBUG_INFO,"%a:%d ECC object free\n ",__FUNCTION__, __LINE__));
        EcFree(h->handle);
    }
    return ret;
}


SBCStatus SBC_EcDsaSign(SBCEccCtx *h, TLV_t *hash, LV_t *signature)
{
    SBCStatus ret = SBCOK;

    SBC_RET_VALIDATE_ERRCODE((h != NULL), SBCNULLP);
    SBC_RET_VALIDATE_ERRCODE((hash != NULL), SBCNULLP);
    SBC_RET_VALIDATE_ERRCODE((hash->value != NULL), SBCNULLP);
    SBC_RET_VALIDATE_ERRCODE((hash->length > 0), SBCZEROL);
    SBC_RET_VALIDATE_ERRCODE((signature != NULL), SBCNULLP);
    SBC_RET_VALIDATE_ERRCODE((signature->value != NULL), SBCNULLP);
    //SBC_RET_VALIDATE_ERRCODE((signature->length > 0), SBCZEROL);

    if(EcDsaSign(h->handle, 
                 (UINTN)hash->tag, (CONST UINT8 *)hash->value, (UINTN)hash->length,
                 (UINT8 *)signature->value, (UINTN *)&signature->length) != TRUE) {
        eprint("ECDSA create signature fail"); 

        ret = SBCBADFMT;
        goto errdone;
    }

    ret = SBCOK;

errdone:

    return ret;


}

//static INTN _do_veeify_message(UINT8 *verifymsg, UINT8 *original, UINTN cmplen)
//{
//    return CompareMem(verifymsg, original, cmplen);
//
//}


SBCStatus SBC_EcDsaVerify(SBCEccCtx *h, TLV_t *hash, LV_t *signature)
{
    SBCStatus ret = SBCOK;

    SBC_RET_VALIDATE_ERRCODE((h != NULL), SBCNULLP);
    SBC_RET_VALIDATE_ERRCODE((hash != NULL), SBCNULLP);
    SBC_RET_VALIDATE_ERRCODE((hash->value != NULL), SBCNULLP);
    SBC_RET_VALIDATE_ERRCODE((hash->length > 0), SBCZEROL);
    SBC_RET_VALIDATE_ERRCODE((signature != NULL), SBCNULLP);
    SBC_RET_VALIDATE_ERRCODE((signature->value != NULL), SBCNULLP);
    //SBC_RET_VALIDATE_ERRCODE((signature->length > 0), SBCZEROL);


    if(EcDsaVerify(h->handle,
                 (UINTN)hash->tag, (CONST UINT8 *)hash->value, (UINTN)hash->length,
                 (UINT8 *)signature->value, signature->length) != TRUE) {
        eprint("ECDSA verify fail");

        ret = SBCBADFMT;
        goto errdone;
    }


    ret = SBCOK;

errdone:

    return ret;


}

SBCStatus  SBC_ConvertRawKeyPem(
                                    IN  CONST UINT8  *DerData,
                                    IN  UINTN         DerSize,
                                    IN  CONST CHAR8  *PemHeader,
                                    IN  CONST CHAR8  *PemFooter,
                                    OUT CHAR8       **PemKey,
                                    OUT UINTN        *PemKeySize)
{
    SBCStatus ret = SBCOK;
    EFI_STATUS  Status;
    UINTN       Base64Size = 0;
    UINT8      *Base64Encoded = NULL;
    CHAR8      *PemBuffer = NULL;
    UINTN       HeaderLen, FooterLen;
    UINTN       NewlineCount, TotalSize;
    UINTN       i, j, Offset;

    SBC_RET_VALIDATE_ERRCODEMSG(((DerData != NULL) || (PemKey != NULL) || (PemKeySize != NULL)),
                                 SBCNULLP,
                                 "ECC key context creaet fail");

    //  Base64-encode the DER data
    Status = Base64Encode(DerData, DerSize, NULL, &Base64Size);
//  dprint("Base64Encode : %d, %d", Status, Base64Size);
//  Status = Base64Encode(DerData, DerSize, NULL, &Base64Size);
//  dprint("Base64Encode : %d, %d", Status, Base64Size);
//  if (EFI_ERROR(Status)) {
//      eprint("Base64-encode the DER data");
//      ret = SBCFAIL;
//      goto errdone;
//  }
    Base64Encoded = AllocateZeroPool(Base64Size);
    
    SBC_RET_VALIDATE_ERRCODEMSG((Base64Encoded != NULL), SBCNULLP, "Base64Encoded AlloctaeZeroPool fail");

    Status = Base64Encode(DerData, DerSize, (CHAR8 *)Base64Encoded, &Base64Size);
    //dprint("Base64Encode : %d", Status);
    if (EFI_ERROR(Status)) {
        eprint("Base64-encode the DER data");
        ret = SBCFAIL;
        goto errdone;
    }

    // Insert line breaks every 64 characters
    // Claculate how many newline characters will be inserted.
    NewlineCount = (Base64Size % 64 == 0) ? (Base64Size / 64) - 1 : (Base64Size / 64);

    // Prepare final PEM string size 
    //   Final PEM = Header + newline + Base64 Encoded text (with newlines inserted) + newline + Footer + newline + null terminator.

    HeaderLen  = AsciiStrLen(PemHeader);
    FooterLen  = AsciiStrLen(PemFooter);
    TotalSize = HeaderLen + 1
            + Base64Size + NewlineCount
            + 1 + FooterLen + 1
            + 1;  // For the null terminator

    PemBuffer = AllocateZeroPool(TotalSize);
    SBC_RET_VALIDATE_ERRCODEMSG((PemBuffer != NULL), SBCNULLP, "PemBuffer AlloctaeZeroPool fail");
    

    // Build the PEM string
    Offset = 0;
    // Copy header and newline:
    CopyMem(PemBuffer + Offset, PemHeader, HeaderLen);
    Offset += HeaderLen;
    PemBuffer[Offset++] = '\n';

    // Insert Base64 data with newlines every 64 characters.
    for (i = 0, j = 0; i < Base64Size; i++, j++) {
        PemBuffer[Offset++] = (CHAR8)Base64Encoded[i];
        if (((j + 1) % 64 == 0) && ((i + 1) < Base64Size)) {
            PemBuffer[Offset++] = '\n';
            j = -1; // reset j as we just inserted a newline
        }
    }
    PemBuffer[Offset++] = '\n';

    // Copy footer and final newline.
    CopyMem(PemBuffer + Offset, PemFooter, FooterLen);
    Offset += FooterLen;
    PemBuffer[Offset++] = '\n';

    // Null-terminate the PEM string.
    PemBuffer[Offset] = '\0';

    *PemKey     = PemBuffer;
    *PemKeySize = Offset;

errdone:

    if(Base64Encoded != NULL) {
        FreePool(Base64Encoded);
    }
    return ret;

}

SBCStatus  SBC_DICESeedKeyPair(UINT8 *dice_seed, at_key_t *key)
{
    SBCStatus ret = SBCOK;

    int ecret = 0;
    EC_KEY *ec_key = NULL;
    EC_GROUP *group = NULL;
    BIGNUM *priv_bn = NULL;
    const BIGNUM *order  =NULL;
    BN_CTX *ctx = NULL;
    EC_POINT *pub_point = NULL;
    CONST EC_POINT *EcPoint = NULL;
    BIGNUM          *BnX;
    BIGNUM          *BnY;
    CONST BIGNUM  *bn_q;
    UINTN           HalfSize;
    INTN            XSize;
    INTN            YSize;


    // Generate hte ECC key structure using the secp256r1
    ec_key = EC_KEY_new_by_curve_name(NID_X9_62_prime256v1);
    SBC_RET_VALIDATE_ERRCODEMSG((ec_key != NULL), SBCNULLP, "ECC key context creaet fail");

    group = (EC_GROUP *)EC_KEY_get0_group(ec_key);
    //SBC_RET_VALIDATE_ERRCODEMSG((ec_key != NULL), SBCNULLP, "ECC key context creaet fail");
    ctx = BN_CTX_new();
    SBC_RET_VALIDATE_ERRCODEMSG((ctx != NULL), SBCNULLP, "BN context creaet fail");

    // Obtain the order of curve ( available range : [1, n-1])
    order = EC_GROUP_get0_order(group);

    // Convert from DICE seed to bignum
    priv_bn=  BN_bin2bn(dice_seed, 32, NULL);
    SBC_RET_VALIDATE_ERRCODEMSG((priv_bn != NULL), SBCNULLP, "Convert from DICE seed to bignum fail");

    // Modular operation of seed into order: determining the privat ekey within the valid range
    if(!BN_mod(priv_bn, priv_bn, order, ctx)) {
        eprint("BN_mod operation fail");
        ret = SBCFAIL;
        goto errdone;
    }

    // Set the private key
    ecret = EC_KEY_set_private_key(ec_key, priv_bn);
    SBC_RET_VALIDATE_ERRCODEMSG((ecret != 0), SBCFAIL, "Set the private key fail");

    bn_q = EC_KEY_get0_private_key(ec_key);
    BN_bn2bin(bn_q, key->d);

    // Public key calculate : P = d * G
    pub_point = EC_POINT_new(group);
    SBC_RET_VALIDATE_ERRCODEMSG((pub_point != NULL), SBCNULLP, "Public point nill");

    ecret = EC_POINT_mul(group, pub_point, priv_bn, NULL, NULL, ctx);
    SBC_RET_VALIDATE_ERRCODEMSG((ecret != 0), SBCFAIL, "EC_POINT_mul fail");

    // ECC pubilckey set
    ecret = EC_KEY_set_public_key(ec_key,pub_point);
    SBC_RET_VALIDATE_ERRCODEMSG((ecret != 0), SBCFAIL, "EC_KEY_set_public_key fail");

    HalfSize = (EC_GROUP_get_degree (group) + 7) / 8;
    dprint("Half size : %d", HalfSize);

    key->dl = HalfSize;
    key->ql = HalfSize * 2;


    EcPoint = EC_KEY_get0_public_key(ec_key);
    SBC_RET_VALIDATE_ERRCODEMSG((EcPoint != NULL), SBCFAIL, "EC_KEY_get0_public_key fail");

    BnX    = BN_new ();
    BnY    = BN_new();
    SBC_RET_VALIDATE_ERRCODEMSG((BnX != NULL), SBCFAIL, "BnX fail");
    SBC_RET_VALIDATE_ERRCODEMSG((BnY != NULL), SBCFAIL, "BnY fail");

    if (EC_POINT_get_affine_coordinates (group, EcPoint, BnX, BnY, NULL) != 1) {
          eprint("EC_POINT_get_affine_coordinates fail");
          ret = SBCFAIL;
          goto errdone;
    }

    XSize = BN_num_bytes (BnX);
    YSize = BN_num_bytes (BnY);
    if ((XSize <= 0) || (YSize <= 0)) {
        eprint("XY size is zero");
        ret = SBCZEROL;
        goto errdone;
    }

    dprint("XSize : %d YSize :%d ", XSize, YSize);

    ZeroMem (key->q.value, key->ql);
    BN_bn2bin(BnX, key->q.qxy.qx);
    BN_bn2bin(BnY, key->q.qxy.qy);

   // BN_bn2bin(BnX, &PublicKey[0 + HalfSize - XSize]);
   // BN_bn2bin(BnY, &PublicKey[HalfSize + HalfSize - YSize]);
    

errdone:
    if(BnX != NULL) {
        BN_free(BnX);
    }

    if(BnY != NULL) {
        BN_free(BnY);
    }

    if(priv_bn != NULL) {
        BN_free(priv_bn);
    }

    if(ctx != NULL) {
        BN_CTX_free(ctx);
    }

    if(ec_key != NULL) {
        EC_KEY_free(ec_key);
    }

    if(pub_point != NULL) {
        EC_POINT_free(pub_point);
    }
    return ret;

}

//#ifdef SBC_ECDSA_TEST_ENABLE
VOID SBC_EcDsa_TestMain(VOID)
{
    SBCEccCtx *ctx;
    SBCStatus ret;

    UINT8 privkey[256];
    UINT8 pubkey[256];
    UINT8 signbuf[66 * 2];
    UINTN keybit = 256;

    TLV_t hash;
    LV_t signature;

    UINT8    HashValue[SHA256_DIGEST_SIZE];
    //UINTN    HashSize;

    ctx = AllocateZeroPool(sizeof *ctx);
    SBC_RET_VALIDATE_ERRCODE((ctx != NULL), SBCNULLP);

    ZeroMem(ctx,sizeof *ctx);
    ctx->pubkey.value = pubkey;
    ctx->pubkey.length = keybit >> 2;
    ctx->privkey.value = privkey;
    ctx->privkey.length = keybit >> 3;
    

    ret = SBC_EccKeyGen(ctx, CRYPTO_NID_SECP256R1);
    SBC_RET_VALIDATE_ERRCODE((ret == SBCOK), SBCFAIL);

    SBC_external_mem_print_bin("Test Private Key", ctx->privkey.value, ctx->privkey.length);
    SBC_external_mem_print_bin("Test Pub Key", ctx->pubkey.value, ctx->pubkey.length);

    hash.tag = CRYPTO_NID_SHA256;
    hash.value = HashValue;
    hash.length = SHA256_DIGEST_SIZE;

    CopyMem((void *)hash.value, (void *)ctx->privkey.value, hash.length);

    signature.value = signbuf;
    signature.length = sizeof signbuf;

    ret = SBC_EcDsaSign(ctx,  &hash,  &signature);
    if(ret != SBCOK) {
        eprint("Do sign fail !!!");
        goto errdone;
    }

    SBC_external_mem_print_bin("Signature", signature.value, signature.length);

    ret = SBC_EcDsaVerify(ctx,  &hash,  &signature);
    if(ret != SBCOK) {
        eprint("Do verify  fail !!!");
        goto errdone;
    }

    dprint("ECDSA verify success~ ~~");





errdone:

    if(ctx->handle) {
        EcFree(ctx->handle);
        ctx->handle = NULL;
    }

    if(ctx) {
        FreePool(ctx);
        ctx = NULL;
    }
    return;

}
//#endif
 


