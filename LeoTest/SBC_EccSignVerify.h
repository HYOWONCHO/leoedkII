#ifndef __SBC_ECCSIGNVERIFY__
#define __SBC_ECCSIGNVERIFY__

#include "SBC_ErrorType.h"


typedef struct _ecc_ctx_t {
    VOID *handle;
    LV_t pubkey;
    LV_t privkey;
    LV_t sharedkey;


    UINTN curveid;
}SBCEccCtx;


SBCStatus SBC_EcCtxSetPubKey(VOID *handle, UINT8 *key, UINTN keylen, UINT32 curveid);
SBCStatus SBC_EcCtxSetPrivKey(VOID *handle, UINT8 *key, UINTN keylen, UINT32 curveid);
SBCStatus SBC_EccKeyGen(SBCEccCtx *h, UINTN curveid);
SBCStatus SBC_GenShareSeucrityKey(SBCEccCtx *h, UINT8 *privkey, UINTN privlen, UINT8 *pubkey, UINTN publen);


#endif
