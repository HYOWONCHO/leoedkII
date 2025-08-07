#include <Uefi.h>
#include <Library/UefiRuntimeServicesTableLib.h>
#include <Library/BaseLib.h>
#include <Library/ResetSystemLib.h>
#include <Library/BaseMemoryLib.h>

#include "SBC_SystemControl.h"
#include "SBC_AntiTampering.h"
#include "SBC_Hashing.h"
#include "SBC_CryptAES.h"
#include "SBC_EccSignVerify.h"

#include "SBC_BootProc.h"
#include "SBC_FileCtrl.h"

//EFI_GUID g_sbc_guid  = {0x1F3F7E80, 0xDB6B, 0x93FA, {0x9E, 0x61, 0x4C, 0x31, 0x3D, 0x3A}};

SBCStatus SBC_FindPrtoSWAndProcessing(UINT8 *deckey, UINT8 *buf, UINTN buflen, UINT8 *decbuf, UINT32 *declen)
{
    SBCStatus ret = SBCOK;
    UINTN enclen = 0;
    [[gnu::unused]] UINT8 *encbuf = NULL;
    UINT8 *iv;
    UINT8 *tag;
    SBC_AESContext aesctx;
    SBC_AESGcmCtx  ctx;
    [[gnu::unused]]  UINT8 shared_secret[SBC_AT_HASH_LEN] = {0, };
    [[gnu::unused]] sw_node_t node_info;

    CopyMem((void *)&enclen, (void *)&buf[0], 4);
    encbuf = &buf[4];
    iv = &buf[4 + enclen];
    tag = &buf[4 + enclen + SBC_AT_IV_LEN];


    if(SBC_HashCompute(NULL, deckey, SBC_AT_HASH_LEN, shared_secret) != SBCOK) {
        eprint("Shared secret key creation is  fail");
        ret = SBCFAIL;
        goto errdone;
    }


    ctx.out.value = (void *)decbuf;
    ctx.out.length = *declen;
    aesctx.gcm = &ctx;
    aesctx.algoid = SBC_CIPHER_AES_GCM;
    //decrypt sw white list 
    SBC_AESGcmSetContext((void *)aesctx.gcm, (void *)shared_secret, (void *)iv, (void *)tag);
    if (SBC_AESGcmDecrypt(&aesctx) != SBCOK) {
        eprint("Protected SW List decrypt fail");
        ret = SBCFAIL;
        goto errdone;
    }
errdone:

    return ret;



}

static BOOLEAN _check_prev_fw(UINTN prev_bnk_id)
{
    if(prev_bnk_id == 0) {
        return FALSE;
    }

    return TRUE;

    // Load the 
}

SBCStatus SBC_BootKeyModeChange(UINT32 newbm, UINT32 newkey, VOID *priv)
{
    SBCStatus ret = SBCOK;
    boot_proc_t *bp = (boot_proc_t *)priv;
    rawprt_hdr_t *hdr = NULL;
    UINT8 wrbuf[512] = {0,};

    hdr = (rawprt_hdr_t *)bp->rawprt_hdr;

    hdr->bootmode = newbm;
    hdr->keymode = newkey;

    dprint();
    SBC_RET_VALIDATE_ERRCODEMSG((bp->blkhnd != NULL), SBCNULLP, "Raw Partition Block IO Handle Nill");

    dprint();
    CopyMem(wrbuf, (void *)hdr, sizeof *hdr);
    SBC_mem_print_bin("Mode Change", wrbuf, 512);
    // Boot Mode write
    dprint();
    ret = SBC_RawPrtBlockWrite(bp->blkhnd,(UINT8 *)wrbuf, 512,0);
    SBC_RET_VALIDATE_ERRCODEMSG((ret == SBCOK), ret, "Boot and Key mode write fail");


errdone:

    return ret;
}


static VOID _sbc_abnormal_processing(VOID *priv)
{
    //SBCStatus ret = SBCOK;

    boot_proc_t *bp = (boot_proc_t *)priv;

    // Check the key mode
    switch(bp->km) {
    case KEY_MODE_NORMAL:
        // Check which existense the previously firmware 
        if(_check_prev_fw(bp->pvs_sw_bnk) != TRUE) {
            // Boot Mode changes from Normmal to Factory
            SBC_BootKeyModeChange(BOOT_MODE_FACTORY, KEY_MODE_UPDATE, priv);
        }
        else {
            SBC_BootKeyModeChange(BOOT_MODE_RECOVERY, KEY_MODE_UPDATE, priv);

        }
        break;
    default:
        goto errdone;
    }

errdone:

    return;

}

static SBCStatus _update_behavior_for_km(void *priv)
{
    SBCStatus ret = SBCOK;
    boot_proc_t *bp = (boot_proc_t *)priv;

    switch(bp->bootst) {
    case SB_PROC_ST_ABNRAM:
        break;
    case SB_PROC_ST_NRMA:
        dprint("Base Answer re-encrypt and write in Update Mode");
        // Base answer re-encrypt using Migration Key 
        ret = SBC_BaseAnswerEncryptStore(bp->blkhnd, 
                                         ((LV_t *)bp->baseansr)->value,
                                         ((LV_t *)bp->baseansr)->length,
                                         ((atp_ident_t *)bp->keyinfo)->migid,
                                         ATP_IDENT_KEY_STG);

        if(ret != SBCOK) {
            eprint("Detection SBC_tamper_OSID derived answer "
                            "mismatched known answer");
            goto errdone;
        }

        dprint();
//      ret = SBC_BootKeyModeChange(BOOT_MODE_RECOVERY, KEY_MODE_NORMAL, priv);
//      if(ret != SBCOK) {
//          eprint("Boot Mode and Key Mode change fail");
//          goto errdone;
//      }

        break;
    default:
        ret = SBCINVPARAM;
        goto errdone;
    }


errdone:

    return ret;
}

static SBCStatus  SBC_UpdateBootPorcsesing(void *priv)
{
    SBCStatus ret = SBCOK;
    boot_proc_t *bp = (boot_proc_t *)priv;
    
    switch(bp->km) {
    case KEY_MODE_NORMAL:
        dprint();
        ret = _update_behavior_for_km(priv);
        dprint();
        break;
    case KEY_MODE_BOOT:
        break;
    case KEY_MODE_UPDATE:
        dprint();
        ret = _update_behavior_for_km(priv);
        dprint();
        break;
    case KEY_MODE_NONE:
        break;
    default:
        eprint("Unknown Key mode over the Update Boot Mode");
        ret = SBCINVPARAM;
        goto errdone;
    }

errdone:
    if(ret != SBCOK) {
    }
    return ret;
}

void SBC_RecoveryBootProcessing(VOID *priv)
{
    SBCStatus ret = SBCOK;
    //sb_rcv_proc_t *p = NULL;
    boot_proc_t   *bt_proc = NULL; // BOot process
    [[gnu::unused]] UINT8 sk[BASE_ANS_KEY_STR] = {0,}; // Secret key for Protected SW 
    [[gnu::unused]] LV_t sysconf;
    [[gnu::unused]] sw_whitels_t  auth_list; 


    // bug -->
    //p = (sb_rcv_proc_t *)priv;
    bt_proc = (boot_proc_t *)priv;

    //p->baseans  = bt_porc

    // Boot Mode is Recovery and Boot Status is abnormal 
    // Boot Mode is change from Recovery to Factory
    // Than, Key mode is Boot
    if(bt_proc->bootst == SB_PROC_ST_ABNRAM) {
        SBC_BootKeyModeChange(BOOT_MODE_FACTORY, KEY_MODE_BOOT, priv);
        SBC_RebootSystem();
        return;
    }

    if(_check_prev_fw(bt_proc->pvs_sw_bnk) != TRUE) {
        eprint("Previously Boot Firmware not existense");
        // System Shutdown
        goto errdone;
       
    }

    // Create the OSID

    // Baseanswer Ecnrypt and Store
    ret = SBC_BaseAnswerEncryptStore(
                    bt_proc->blkhnd,
                    ((LV_t *)bt_proc->baseansr)->value,
                    ((LV_t *)bt_proc->baseansr)->length,
                    ((atp_ident_t *)bt_proc->keyinfo)->osid,
                    BASE_ANS_KEY_STR
    );


    SBC_RET_VALIDATE_ERRCODEMSG((ret == SBCOK)
                                ,ret, 
                                "Detection SBC_tamper_OSID derived answer "
                                "mismatched known answer");


#ifdef SAT_PROT_SW_ENABLE
    // Create the secret key
    ret = SBC_HashCompute(NULL, p->osid, BASE_ANS_KEY_STR, sk);
    SBC_RET_VALIDATE_ERRCODEMSG((ret == SBCOK), ret, "Secret key create fail");

    // Load protected SW  List
    ret = SBC_LoadSystemSetting(bt_proc->blkhnd, (VOID *)&sysconf);
    SBC_RET_VALIDATE_ERRCODEMSG((ret == SBCOK),
                                ret,
                                "Load System Setting repository fail");

    CopyMem((void *)&auth_list, 
            (void *)&((UINT8 *)sysconf.value)[SYS_CONF_SW_LIST_OFS],
            sizeof auth_list);
#endif

    switch(bt_proc->bootst) {
    case SB_PROC_ST_NRMA:
        switch(bt_proc->km) {
        case KEY_MODE_BOOT:
        case KEY_MODE_UPDATE:
            ret = SBC_BootKeyModeChange(BOOT_MODE_NORMAL, KEY_MODE_NORMAL, priv);
            break;
        default:
            eprint("Not support key mode for Recovery Normal Boot");
            goto errdone;
        }

        break;
    case SB_PROC_ST_ABNRAM:
        ret = SBC_BootKeyModeChange(BOOT_MODE_FACTORY, KEY_MODE_BOOT, priv);
        break;
    default:
        eprint("Unknown Secure Boot status");
        goto errdone;
    }

    if(ret != SBCOK) {
        eprint("Boot and Key mode change fail");
        goto errdone;
    }

    SBC_RebootSystem();
    return;

errdone:
    SBC_ShutdownSystem();
    return ;
}


static void _update_reset_check_and_behavior(VOID *priv)
{
    boot_proc_t *bp = (boot_proc_t *)priv;
    dprint("Key mode : %d", bp->km);
    switch(bp->km) {
    case KEY_MODE_NORMAL:
        dprint("Boot State : %d", bp->bootst);
        switch(bp->bootst) {
        case SB_PROC_ST_NRMA:
            dprint();
            SBC_BootKeyModeChange(BOOT_MODE_RECOVERY, KEY_MODE_NORMAL, priv);
            break;
        case SB_PROC_ST_ABNRAM:
            if(bp->pvs_sw_bnk) {
                dprint();
                // if existense the previously firmware 
                SBC_BootKeyModeChange(BOOT_MODE_RECOVERY, KEY_MODE_UPDATE, priv);
            }
            else {
                dprint();
                SBC_BootKeyModeChange(BOOT_MODE_FACTORY, KEY_MODE_UPDATE, priv);
            }
            break;
        default:
            eprint("Unknown Boot Status");
            break;
        }

        SBC_RebootSystem();
        
        break;
    default:
        dprint("Unknown Key Mode");
        break;
    }
    dprint();


    return;
}

VOID SBC_ResetScenario(VOID *priv)
{
    boot_proc_t *bp = (boot_proc_t *)priv;
    dprint("Boot Mode : %d", bp->bm);
    switch(bp->bm) {
    case BOOT_MODE_UPDATE:
        {   
            dprint();
            _update_reset_check_and_behavior(priv);
        }
        break;
    default:
        dprint("Unknown Boot Mode");
        break;
    }


    return;

}


SBCStatus  SBC_SecureBootCheck(VOID *priv)
{
    SBCStatus ret = SBCOK;
    //VOID        *new_hnd = NULL;
    //BOOLEAN   bret = FALSE;

    LV_t        blob; 
    boot_proc_t *bp = (boot_proc_t *)priv;
    sb_rcv_proc_t srp;
    [[gnu::unused]] UINTN         swcnt = 0;

    ZeroMem((VOID *)&blob, sizeof blob);
    ZeroMem((VOID *)&srp, sizeof srp);

#ifdef SAT_PROT_SW_ENABLE
#error "x1"
    ret = SBC_LoadSystemSetting(bp->blkhnd, (VOID *)&blob);
    SBC_RET_VALIDATE_ERRCODEMSG((ret == SBCOK), ret, "System Setting Load fail");
#endif
    srp.osid = ((atp_ident_t *)bp->keyinfo)->osid;
    srp.migkey = ((atp_ident_t *)bp->keyinfo)->migid;
    srp.baseans = bp->baseansr;
    srp.handle = bp->blkhnd;
#ifdef SAT_PROT_SW_ENABLE
#error "x2"
    // Referencing the address of a buffer regarding the SW LIST 
    //srp.whitels = &((UINT8 *)blob.value)[SYS_CONF_SW_LIST_OFS];;
    srp.whitels = (UINT8 *)(blob.value) + SYS_CONF_SW_LIST_OFS;
    swcnt = ((LV_t *)srp.whitels)->length / sizeof(sw_whitels_t);
#endif

    switch(bp->bm) {
    case BOOT_MODE_NORMAL:
        if(bp->bootst == SB_PROC_ST_ABNRAM) {

            // In case of the Boot Mode is Normal and Boot State is Abnormal.
            _sbc_abnormal_processing(priv);
                // TODO : error processing
            SBC_RebootSystem();
        }

        break;
    case BOOT_MODE_RECOVERY:
        dprint("Block  I/O Handle : 0x%lx",bp->blkhnd);
        SBC_RecoveryBootProcessing(priv);
        break;

    case BOOT_MODE_UPDATE:
        ret = SBC_UpdateBootPorcsesing(priv);
        dprint();
        break;
    default:
      goto errdone;
      //break;
    }

    


errdone:
    SBC_ResetScenario(priv);
    return ret;

}



VOID SBC_RebootSystem(VOID)
{
    Print(L"System Reset ... \n");
    gRT->ResetSystem(EfiResetCold, EFI_SUCCESS, 0, NULL);
    while(TRUE) { };

}


VOID SBC_ShutdownSystem(VOID)
{
    Print(L"System Shutdown ... \n");
    gRT->ResetSystem(EfiResetShutdown, EFI_SUCCESS, 0, NULL);
    while(TRUE) { };
}
