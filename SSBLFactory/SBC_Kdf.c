#include <Library/BaseCryptLib.h>

#include "SBC_ErrorTypes.h"
#include "SBC_TypeDefs.h"

static UINT8  sha256salt[13] = {
  0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09,
  0x0a, 0x0b, 0x0c,
};

static UINT8  sha256info[10] = {
  0xf0, 0xf1, 0xf2, 0xf3, 0xf4, 0xf5, 0xf6, 0xf7, 0xf8, 0xf9,
};

/**
 * @brief Generate the RNG
 *
 * @param[in]   seed      Random seed buffer
 * @param[in]   szseed    Length of seed buffer
 * @param[in]   szrng     Number of Random size
 * @param[out]  rngdata   Random data
 *
 * @return  On success, return the SBCOK, otherwise return approiate value
 */
SBCStatus SBC_RngGeneration(UINT8 *seed, UINTN szseed, UINTN szrng, UINT8 *rngdata) 
{

  BOOLEAN status = TRUE;


  if(seed == NULL || rngdata == NULL) {
    Print(L"%s args point to NULL \n", __FUNCTION__);
    return SBCNULLP;
  }

  if(szseed <= 0 || szrng <= 0) {
    Print(L"%s arg has length os zero \n");
    return SBCZEROL;
  }



  status = RandomSeed(seed, szseed);
  if(status == FALSE) {
    Print(L"RandomSeed fail \n");
    return SBCFAIL;
  }

  status = RandomBytes(rngdata, szrng);
  if(status != TRUE) {
    Print(L"RandomBytes fail \n");
    return SBCFAIL;
  }

  return SBCOK;



}


SBCStatus  SBC_HKdfSha256(kdf_t *k, LV_t  *out)
{
    SBCStatus ret = SBCOK;
    UINT8 *salt = NULL;
    UINT8 *info = NULL;

    UINT8 prkout[KDF_KEY_MAXL] = {0,}; // It is result of Pseudo Random Key 
    BOOLEAN status;

    SBC_RET_VALIDATE_ERRCODEMSG((k != NULL),SBCNULLP, "kdf_t Nill");

    if(k->saltl <= 0) {
        k->saltl = sizeof sha256salt;
        CopyMem(k->salt, sha256salt, k->saltl);
    }

    if(k->infol <= 0) {
        k->infol = sizeof sha256info;
        CopyMem(k->info, sha256info, k->infol);
    }

    // HKDF-SHA-256 digest validation
    // HKDF-Extract (salt,IKM)
    status = HkdfSha256Extract(
                  k->ikm, k->ikml,    // HMAC target data
                  k->salt, k->saltl,  // used to the key on HMAC
                  out->value, out->length
                );

    SBC_RET_VALIDATE_ERRCODEMSG((status != FALSE),SBCFAIL, "HKDF-Extract fail");

//  ZeroMem(out->value, out->length);
//  // HKDF_Expand(PRK, info, L) - OKM
//  status = HkdfSha256Expand(
//              prk, sizeof prk, // Result of Extract
//              k->info, k->infol,
//              out->value, out->length
//      );
//
//  SBC_RET_VALIDATE_ERRCODEMSG((status != FALSE),SBCFAIL, "HKDF_Expand( fail");
//
//  ZeroMem(out->value, out->length);
//  status = HkdfSha256ExtractAndExpand (
//              k->ikm, k->ikml,
//              k->salt, k->saltl,
//              k->info, k->infol,
//              out->value, out->length
//      );
//
//  SBC_RET_VALIDATE_ERRCODEMSG((status != FALSE),SBCFAIL, "HKDF_Expand( fail");






    

errdone:
    return ret;

}
