
#include "SBC_ProtectedSW.h"
#include "SBC_FileCtrl.h"
#include "SBC_BootProc.h"
#include "SBC_AntiTampering.h"

#include "SBC_Config.h"

extern CHAR16 mrgmsg[8192];


SBCStatus SBC_ProtSWGetCnt(VOID *handle, UINTN *cnt)
{
    SBCStatus ret = SBCOK;
    //UINTN sw_list_len;
    //UINTN line;
    UINTN sw_list_size = sizeof(sw_path_t);
    //UINTN readn; 
    boot_proc_t *p = (boot_proc_t *)handle;

    ret  = SBC_RawAlignedReadBlockIO(p->blkhnd, 
                                     SYS_CONF_START_OFS + SYS_CONF_SW_LIST_OFS,
                                     4,
                                     cnt);
    SBC_RET_VALIDATE_ERRCODEMSG((ret == SBCOK), ret, "Protected SW List Cnt read fail");

    dprint("Protected List Cnt %d", *cnt);

    *cnt = *cnt / sw_list_size;

    dprint("Protected SW count = %d", *cnt);

errdone:

    return ret;
}

SBCStatus SBC_GetProtectedSwName(VOID *handle, UINTN st, CHAR8 *sw_name, UINTN sw_name_size)
{
    SBCStatus ret = SBCOK;

    boot_proc_t *p = (boot_proc_t *)handle; 
    UINT8 encbuf[SBC_AT_RP_SYS_CONF_MAX_LEN]  = {0,};
    UINT8 decbuf[SBC_AT_RP_SYS_CONF_MAX_LEN]  = {0,};
    UINT8 dec_key[SBC_AT_RP_KEY_LEN] = {0,};
    UINTN enclen = 0ULL;
    UINTN rd_ofs = SYS_CONF_START_OFS + SYS_CONF_SW_LIST_OFS;
    UINT8 iv[SBC_AT_RP_IV_LEN], tag[SBC_AT_RP_TAG_LEN];

    UINT8 *shared_secret = NULL;
    SBC_AESContext aesctx;
    SBC_AESGcmCtx  ctx;


    CHAR16 err_out_key_val[128] = {0,};

    ret = SBC_DeviceSecuirtyKeyCreate(dec_key);
    SBC_RET_VALIDATE_ERRCODEMSG((ret == SBCOK), ret, "Protected SW List Cnt read fail");

    ret  = SBC_RawAlignedReadBlockIO(p->blkhnd, 
                                     rd_ofs,
                                     SBC_RAW_PRTHDR_LEN_OFS,
                                     enclen);
    SBC_RET_VALIDATE_ERRCODEMSG((ret == SBCOK), ret, "Protected SW List Cnt read fail");

    

    //
    // Reading encrypted protected software
    //
    rd_ofs += SBC_RAW_PRTHDR_LEN_OFS;
    ret  = SBC_RawAlignedReadBlockIO(p->blkhnd, 
                                 rd_ofs,
                                 enclen,
                                 encbuf);

    //
    // Reading  iv
    //
    rd_ofs += enclen;
    ret  = SBC_RawAlignedReadBlockIO(p->blkhnd, 
                                 rd_ofs,
                                 SBC_AT_RP_IV_LEN,
                                 iv);


    //
    // Reading tag
    //
    rd_ofs += SBC_AT_RP_IV_LEN;
    ret  = SBC_RawAlignedReadBlockIO(p->blkhnd, 
                                 rd_ofs,
                                 SBC_AT_RP_TAG_LEN,
                                 tag);


    ( p->bm == BOOT_MODE_UPDATE ) ? shared_secret = ((atp_ident_t *)p->keyinfo)->migid : shared_secret = dec_key;




    //
    // Decrypt the Protected SW 
    //

    ctx.msg.value = (void *)encbuf;
    ctx.out.value = (void *)decbuf;
    ctx.msg.length = ctx.out.length = enclen;

    SBC_AESGcmSetContext((void *)aesctx.gcm, 
                     (void *)shared_secret, 
                     (void *)iv, 
                     (void *)tag);

    if (SBC_AESGcmDecrypt(&aesctx) != SBCOK) {
        SBC_LogHexToStrChar16(shared_secret, 32, err_out_key_val, sizeof(err_out_key_val)/sizeof(err_out_key_val[0]),  FALSE, 0);
        UnicodeSPrint(mrgmsg,  sizeof mrgmsg, L"SBC_ProtSW_Update Failed to decrypt (%s) \n", err_out_key_val);
        sbc_err_sysprn(SBC_LOG_CMN_PRIO_ERR, 2,
                 L"AT_BOOT",
                 L"SSBL",
                 L"SAT",
                 5,
                 L"Detection",
                 mrgmsg);
        ret = SBCENCFAIL;
        goto errdone;
    }

errdone:

    return ret;

}


SBCStatus SBC_ProtSWDecrypt(VOID *handle, UINT8 *key, UINT8 *decbuf ,UINT32 *declen)
{
    SBCStatus ret = SBCOK;
    boot_proc_t *p = (boot_proc_t *)handle;
    UINTN sw_list_line = 0ULL;
    UINTN x = 0;


    SBC_RET_VALIDATE_ERRCODEMSG((p != NULL), SBCNULLP, "Invalid Handle Object");

    ret = SBC_ProtSWGetCnt((VOID *)p, &sw_list_line);
    SBC_RET_VALIDATE_ERRCODEMSG((ret == SBCOK), ret, "Protected SW Count read fail");

    for( x = 0; x < sw_list_line; x++) {

    }




errdone:

    return ret;

}

