#include <Uefi.h>
#include <Library/UefiRuntimeServicesTableLib.h>
#include <Library/BaseLib.h>
#include <Library/ResetSystemLib.h>
#include <Library/BaseMemoryLib.h>
#include <Library/MemoryAllocationLib.h>

#include "SBC_SystemControl.h"
#include "SBC_AntiTampering.h"
#include "SBC_Hashing.h"
#include "SBC_CryptAES.h"
#include "SBC_EccSignVerify.h"

#include "SBC_BootProc.h"
#include "SBC_FileCtrl.h"
#include "SBC_Kdf.h"
#include "SBC_ProtectedSW.h"

//EFI_GUID g_sbc_guid  = {0x1F3F7E80, 0xDB6B, 0x93FA, {0x9E, 0x61, 0x4C, 0x31, 0x3D, 0x3A}};


static 
SBCStatus 
__attribute__((unused))
SBC_FindPrtoSWAndProcessing(UINT8 *deckey, 
                            UINT8 *buf, 
                            UINTN buflen, 
                            UINT8 *decbuf, 
                            UINT32 *declen)
{
    SBCStatus ret = SBCOK;
    UINTN enclen = 0;
    [[gnu::unused]] UINT8 *encbuf = NULL;
    UINT8 *iv;
    UINT8 *tag;
    SBC_AESContext aesctx;
    SBC_AESGcmCtx  ctx;
    [[gnu::unused]]  UINT8 shared_secret[SBC_AT_HASH_LEN] = {0, };
    [[gnu::unused]] sbc_sw_node_t node_info;

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
    SBC_AESGcmSetContext((void *)aesctx.gcm, 
                         (void *)shared_secret, 
                         (void *)iv, 
                         (void *)tag);
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

    //dprint();
    SBC_RET_VALIDATE_ERRCODEMSG((bp->blkhnd != NULL), SBCNULLP, "Raw Partition Block IO Handle Nill");

    //dprint();
    CopyMem(wrbuf, (void *)hdr, sizeof *hdr);
    SBC_mem_print_bin("Mode Change", wrbuf, 128);
    // Boot Mode write
    ret = SBC_RawPrtBlockWrite(bp->blkhnd,(UINT8 *)wrbuf, 512,0);
    SBC_RET_VALIDATE_ERRCODEMSG((ret == SBCOK), ret, "Boot and Key mode write fail");


errdone:

    return ret;
}


VOID _sbc_abnormal_processing(VOID *priv)
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

static SBCStatus _base_answer_decrypt_encrypt(void *priv)
{
    SBCStatus ret = SBCOK;
#if 1
    boot_proc_t *bp = (boot_proc_t *)priv;
    UINT8 *answer_key = ((atp_ident_t *)bp->keyinfo)->migid;
#else

    boot_proc_t *bp = (boot_proc_t *)priv;
    UINT8 answer_key[32] = {
    	0xE3, 0xF7, 0x9F, 0x34, 0x0D, 0x9F, 0x1B, 0xC2, 0x0E, 0xC8, 0x96, 0x52,
    	0x3D, 0x50, 0x28, 0xAF, 0x5E, 0x73, 0x34, 0xD6, 0x99, 0x2D, 0xD2, 0xC4,
    	0x4D, 0xBE, 0xDA, 0x06, 0x0D, 0x84, 0x47, 0xD4
    };
#endif

    SBC_AESContext aesctx;
    SBC_AESGcmCtx  ctx;
    UINT8 decbuf[BASE_ANS_STREAM_LEN] = {0,};
    


    ZeroMem((void *)&ctx, sizeof ctx);
    ZeroMem((void *)&aesctx, sizeof aesctx);

    ret = SBC_BaseAnswerValidate(bp->blkhnd,
                                 decbuf, 
                                 SBC_BASE_ANSR_LEN,
                                 answer_key,
                                 ATP_IDENT_KEY_STG,
                                 FALSE);

    SBC_RET_VALIDATE_ERRCODEMSG((ret == SBCOK),ret, "SBC_BaseAnswer obtain fail");


    SBC_mem_print_bin("Mig ID BaseAnswer", decbuf, 16);

    ret = SBC_BaseAnswerEncryptStore(bp->blkhnd, 
                                 decbuf,
                                 SBC_BASE_ANSR_LEN,
                                 ((atp_ident_t *)bp->keyinfo)->osid,
                                 ATP_IDENT_KEY_STG);

    SBC_RET_VALIDATE_ERRCODEMSG((ret == SBCOK), ret, "SBC_BaseAnswerEncryptStore  fail");
errdone:

    return ret;
}

static SBCStatus _proetcted_sw_re_enc_dec(VOID *handle)
{
    SBCStatus ret = SBCOK;
    boot_proc_t *bp = (boot_proc_t *)handle;

    UINT8 deckey[SBC_AT_RP_KEY_LEN] = {0, };
    UINT8 enckey[SBC_AT_RP_KEY_LEN] = {0, };



    ret = SBC_HashCompute(NULL, 
                          ((atp_ident_t *)bp->keyinfo)->migid,
                          SBC_AT_RP_KEY_LEN,
                          deckey);
    SBC_RET_VALIDATE_ERRCODEMSG(!(ret != SBCOK), ret, 
                                "Failed to Dec secret key creation");

    ret = SBC_HashCompute(NULL, 
                          ((atp_ident_t *)bp->keyinfo)->osid,
                          SBC_AT_RP_KEY_LEN,
                          enckey);
    SBC_RET_VALIDATE_ERRCODEMSG(!(ret != SBCOK), ret, 
                                "Failed to Enc secret key creation");



    ret = SBC_ProtSWDecrypt((VOID *)bp, 
                            enckey,
                            deckey,
                            NULL, NULL);
    SBC_RET_VALIDATE_ERRCODEMSG(!(ret != SBCOK),
                                ret,
                                "Failed to Re-crypto");


    sbc_err_sysprn(SBC_LOG_CMN_PRIO_INFO, 2,
               SYS_LOG_HOST_BOOT,
               SYS_LOG_APP_NAME,
               SYS_LOG_CSC_NAME,
               1,
               SYS_LOG_EVT_VALDIATION,
               L"SBC_ProtSW_Update Protected Software update success");

errdone:

    if(ret != SBCOK) {
        sbc_err_sysprn(SBC_LOG_CMN_PRIO_ERR, 2,
           SYS_LOG_HOST_BOOT,
           SYS_LOG_APP_NAME,
           SYS_LOG_CSC_NAME,
           1,
           SYS_LOG_EVT_DETECTION,
           L"SBC_ProtSW_Update Failed to update the Protected Software");
    }

    return ret;
}

static SBCStatus _update_behavior_for_km(void *priv)
{
    SBCStatus ret = SBCOK;
    boot_proc_t *bp = (boot_proc_t *)priv;

    switch(bp->bootst) {
    case SB_PROC_ST_ABNRAM:
        // Operation for this is processing in 
        // _update_reset_check_scenario function

        ret = SBCFAIL;

        break;
    case SB_PROC_ST_NRMA:
        dprint("Base Answer re-encrypt and write in Update Mode");

        // Base answer re-encrypt using Migration Key 

        // Base Answer decrypt 

        // Base Answer re-encrypt and store 
//      ret = SBC_BaseAnswerEncryptStore(bp->blkhnd,
//                                       ((LV_t *)bp->baseansr)->value,
//                                       ((LV_t *)bp->baseansr)->length,
//                                       ((atp_ident_t *)bp->keyinfo)->migid,
//                                       ATP_IDENT_KEY_STG);
        ret = _base_answer_decrypt_encrypt((void *)bp);
        if(ret != SBCOK) {
            eprint("Detection SBC_tamper_OSID derived answer "
                            "mismatched known answer");
            goto errdone;
        }



        ret =  _proetcted_sw_re_enc_dec((void *)bp);
        if(ret != SBCOK) {
            eprint("Detection _proetcted_sw_re_enc_dec ");
            goto errdone;
        }

        ret = SBC_BootKeyModeChange(BOOT_MODE_RECOVERY, KEY_MODE_NORMAL, priv);
        if(ret != SBCOK) {
            eprint("Boot Mode and Key Mode change fail");
            goto errdone;
        }

        break;
    default:
        ret = SBCINVPARAM;
        goto errdone;
    }


errdone:

    // 
    // 
    //
    if(ret != SBCOK) {
        if(_check_prev_fw(bp->pvs_sw_bnk) == TRUE) {
            // Previously exist in Raw Part.
            SBC_BootKeyModeChange(BOOT_MODE_RECOVERY,
                                  KEY_MODE_UPDATE,
                                  priv);
        }
        else {
            SBC_BootKeyModeChange(BOOT_MODE_FACTORY,
                                  KEY_MODE_UPDATE,
                                  priv);
        }
    }

    return ret;
}


static SBCStatus __attribute__((unused)) _protected_sw_rewrite(VOID *priv) 
{

    SBCStatus ret = SBCOK;
    UINT8 secret_key[SYS_OSID_KEY_LEN] = {0, };
    boot_proc_t *bp = NULL; 
    UINT8   *blob = NULL;       // Binary or Byte Large Object
    UINT32  blob_len = 0;

    SBC_RET_VALIDATE_ERRCODEMSG((priv != NULL), 
                                SBCNULLP,
                                "Invalid Blob Parameter");

    bp = (boot_proc_t *)priv;

    ret = SBC_HashCompute(NULL, 
                          ((atp_ident_t *)bp->keyinfo)->migid,
                          SYS_OSID_KEY_LEN,
                          secret_key);

    SBC_RET_VALIDATE_ERRCODEMSG((ret == SBCOK),
                                ret,
                                "Secret Key create fail");

    ret = SBC_ProtectedSWRead(bp->blkhnd,
                              (void **)&blob,
                              &blob_len,
                              bp->curr_sw_bnk);


    SBC_RET_VALIDATE_ERRCODEMSG((ret == SBCOK),
                                ret,
                                "Protected SW Read fail");

    // 


errdone:

    if(blob != NULL) {
        FreePool(blob);
        blob = NULL;
    }

    return ret;
}
                                       

static SBCStatus  SBC_UpdateBootPorcsesing(void *priv)
{
    SBCStatus ret = SBCOK;
    boot_proc_t *bp = (boot_proc_t *)priv;
    
    switch(bp->km) {
    case KEY_MODE_NORMAL:
        //dprint();
        ret = _update_behavior_for_km(priv);
        //dprint();
        break;
    case KEY_MODE_BOOT:
        break;
    case KEY_MODE_UPDATE:
        //dprint();
        ret = _update_behavior_for_km(priv);
        //dprint();
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
        eprint("Update Operation Not Permit !!!");
        bp->bootst = SB_PROC_ST_ABNRAM;
    }
    return ret;
}

static SBCStatus _store_fw_os_keypair_store(VOID *priv, VOID *fwid, VOID *osid)
{ 
    SBCStatus ret = SBCOK;

    UINT8 *buf = NULL;
    UINT32 id_len = 0;
    UINT32 cpy_offset = 0;

    UINT8 *enckey[SYS_OSID_KEY_LEN] = {0,};
    SBC_AESContext aesctx;
    SBC_AESGcmCtx  ctx;

    UINT8 auth_iv[SBC_AT_IV_LEN] = {0, };
    UINT8 auth_tag[SBC_AT_TAG_LEN] = {0, };

    UINT8 encbuf[SBC_AT_TAG_LEN] = {0, };

    at_key_t fw_key;
    at_key_t os_key;
    boot_proc_t *bp = (boot_proc_t *)priv;
    UINT32 rdlen = 0;

    UINTN lba = 0;
    rawprt_hdr_t h_rawptrheader;


    ret = SBC_DICESeedKeyPair((UINT8 *)fwid, &fw_key);
    if( ret != SBCOK ) {
        SBC_BuildHexFormattedMessage(
                (CONST VOID *)fwid, 32,
                L"SBC_Dice_Key Failed the Create FWID key-pair (%s)\n",
                mrgmsg, sizeof mrgmsg);

        sbc_err_sysprn(SBC_LOG_CMN_PRIO_ERR, 2,
                 SYS_LOG_HOST_BOOT,
                 SYS_LOG_APP_NAME,
                 SYS_LOG_CSC_NAME,
                 1,
                 L"Detectoin",
                 mrgmsg);
        goto errdone;
    }
    //SBC_RET_VALIDATE_ERRCODEMSG((ret == SBCOK), ret, "FWID key pair create fail");

    ret = SBC_DICESeedKeyPair((UINT8 *)osid, &os_key);
    if( ret != SBCOK ) {
        SBC_BuildHexFormattedMessage(
                (CONST VOID *)osid, 32,
                L"SBC_Dice_Key Failed the Create OSID key-pair (%s)\n",
                mrgmsg, sizeof mrgmsg);

        sbc_err_sysprn(SBC_LOG_CMN_PRIO_ERR, 2,
                 SYS_LOG_HOST_BOOT,
                 SYS_LOG_APP_NAME,
                 SYS_LOG_CSC_NAME,
                 1,
                 L"Detectoin",
                 mrgmsg);
        goto errdone;
    }
    //SBC_RET_VALIDATE_ERRCODEMSG((ret == SBCOK), ret, "OSID key pair create fail");


    // Getting the security key to encrypting.
    ret = SBC_DeviceSecuirtyKeyCreate((VOID *)enckey);
    SBC_RET_VALIDATE_ERRCODEMSG((ret == SBCOK),
                                ret,
                                "Security Key Create fail");

    buf = AllocateZeroPool(ALIGN_VALUE(SYS_SETTING_STORAGE_LEN,512));
    SBC_RET_VALIDATE_ERRCODEMSG((buf != NULL),
                                SBCNULLP,
                                "Allocate Fail");

    lba = (SYS_CONF_START_OFS >> SBC_RAWPRT_DFLT_SHIFT);
    rdlen = ALIGN_VALUE(SYS_SETTING_STORAGE_LEN,512);
    ret = SBC_RawPrtReadBlock(bp->blkhnd,
                              buf,
                              &rdlen,
                              lba);
    SBC_RET_VALIDATE_ERRCODEMSG((ret == SBCOK),
                                ret,
                                "System Setting repository read fail");


    // Encrypt
    ctx.out.value = encbuf;
    ctx.out.length = sizeof encbuf;
    aesctx.gcm = &ctx;
    aesctx.algoid = SBC_CIPHER_AES_GCM;

    SBC_RngGeneration((UINT8 *)osid,        // Seed 
                      SYS_OSID_KEY_LEN,
                      SBC_AT_IV_LEN,
                      auth_iv);

    SBC_AESGcmSetContext((void *)aesctx.gcm,
                         (void *)enckey,
                         (void *)auth_iv,
                         (void *)auth_tag);

    ctx.msg.value = (UINT8 *)&fw_key;
    ctx.msg.length = sizeof fw_key;
    ctx.out.value = encbuf;
    ctx.out.length = ctx.msg.length;
    ret = SBC_AESGcmEncrypt(&aesctx);
    SBC_RET_VALIDATE_ERRCODEMSG((ret == SBCOK),
                                ret,
                                "Firmware ID Encrypt fail");


    //
    // |------|-------|------|------|
    // | len  | data  |  iv  |  tag |
    // |------|-------|------|------|
    //

    // Copy the Length for Ecnrypt Data
    cpy_offset = SYS_CONF_OSID_CRT_OFS;
    id_len = ctx.out.length;
    // Copy Lengh
    CopyMem(&buf[cpy_offset], &id_len, sizeof id_len);
    cpy_offset += sizeof id_len;
    // Copy Encrypt Data for FWID 
    CopyMem(&buf[cpy_offset],
            encbuf,
            id_len);
    cpy_offset += id_len;

    // IV copy
    CopyMem(&buf[cpy_offset], 
            auth_iv,
            SBC_AT_IV_LEN);
    cpy_offset += SBC_AT_IV_LEN;

    // Tag copy
    CopyMem(&buf[cpy_offset], 
            auth_tag,
            SBC_AT_TAG_LEN);
    cpy_offset += SBC_AT_TAG_LEN;


    // Previously used TAG buffer initialize to zero 
    ZeroMem((VOID *)auth_tag, sizeof auth_tag);

    ctx.msg.value = (UINT8 *)&os_key;
    ctx.msg.length = sizeof os_key;
    ctx.out.value = encbuf;
    ctx.out.length = ctx.msg.length;
    ret = SBC_AESGcmEncrypt(&aesctx);
    SBC_RET_VALIDATE_ERRCODEMSG((ret == SBCOK),
                                ret,
                                "OSID ID Encrypt fail");



    // The OSID  key pair store in the Raw Partition

    // Copy the Length for Ecnrypt Data
    cpy_offset = SYS_CONF_OSID_CRT_OFS;
    id_len = ctx.out.length;
    // Copy Lengh
    CopyMem(&buf[cpy_offset], &id_len, sizeof id_len);
    cpy_offset += sizeof id_len;
    // Copy Encrypt Data for FWID 
    CopyMem(&buf[cpy_offset],
            encbuf,
            id_len);
    cpy_offset += id_len;

    // IV copy
    CopyMem(&buf[cpy_offset], 
            auth_iv,
            SBC_AT_IV_LEN);
    cpy_offset += SBC_AT_IV_LEN;

    // Tag copy
    CopyMem(&buf[cpy_offset], 
            auth_tag,
            SBC_AT_TAG_LEN);
    cpy_offset += SBC_AT_TAG_LEN;



    ret = SBC_RawPrtBlockWrite(bp->blkhnd,
                               buf,
                               ALIGN_VALUE(SYS_SETTING_STORAGE_LEN,512),
                               lba);

    if(ret != SBCOK) {
        eprint("Block Write Fail for System Setting Repository");
        goto errdone;
    }



    id_len = 512;
    ret = SBC_RawPrtReadBlock(bp->blkhnd,
                             buf,
                              &id_len,
                              0);
    if(ret != SBCOK) {
        eprint("Block Read Fail for Raw-Partition Header");
        goto errdone;
    }

    CopyMem((void *)&h_rawptrheader, buf, 128);

    h_rawptrheader.rcvmode = 1;

    CopyMem((void *)buf, 
            (void *)&h_rawptrheader, 
            sizeof h_rawptrheader);

    ret = SBC_RawPrtBlockWrite(bp->blkhnd,
                         buf,
                         id_len,
                         0);
    if(ret != SBCOK) {
        eprint("Block Write Fail for Raw-Partition Header");
        goto errdone;
    }
errdone:

    if(buf != NULL) {
        FreePool(buf);
        buf = NULL;
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
        SBC_BootKeyModeChange(BOOT_MODE_FACTORY, KEY_MODE_BOOT, priv);
        SBC_RebootSystem();
        return;
//      eprint("Previously Boot Firmware not existense");
//      // System Shutdown
//      goto errdone;
       
    }

    ret = _store_fw_os_keypair_store(priv, 
                               ((atp_ident_t *)bt_proc->keyinfo)->fwid,
                               ((atp_ident_t *)bt_proc->keyinfo)->osid);

    if(ret != SBCOK) {
        eprint("_store_fw_os_keypair_store fail, that is, Abnormal");
        bt_proc->bootst = SB_PROC_ST_ABNRAM;
    }
    // Create the OSID

    // TODO : 
    // A. BaseAnswer load from System Setting block of Block IO 
    // B. Decrypt the BaseAnswer using Migration Key
    // C. Re-encrypt the decrypted baseanswer using OSID
    // D. Re-write the baseanswer in System Setting block of Block IO




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
        // later need to create the New API
        switch(bt_proc->km) {
        case KEY_MODE_BOOT:
            dprint("Key Mode Boot");
        //case KEY_MODE_NORMAL:
            // Baseanswer Ecnrypt and Store
            ret = SBC_BaseAnswerEncryptStore(
                            bt_proc->blkhnd,
                            ((LV_t *)bt_proc->baseansr)->value,
                            ((LV_t *)bt_proc->baseansr)->length,
                            ((atp_ident_t *)bt_proc->keyinfo)->osid,
                            BASE_ANS_KEY_STR
            );


            if(ret != SBCOK) {
                //
                // Abnromal state , added at 20251021
                //
                bt_proc->bootst = SB_PROC_ST_ABNRAM;
                SBC_BootKeyModeChange(BOOT_MODE_FACTORY, KEY_MODE_BOOT, priv);
                goto errdone;
            }

            ret = SBC_BootKeyModeChange(BOOT_MODE_NORMAL, KEY_MODE_NORMAL, priv);
            break;
        case KEY_MODE_UPDATE:
            dprint("KEY_MODE_UPDATE");
            ret = SBC_BaseAnswerEncryptStore(
                            bt_proc->blkhnd,
                            ((LV_t *)bt_proc->baseansr)->value,
                            ((LV_t *)bt_proc->baseansr)->length,
                            ((atp_ident_t *)bt_proc->keyinfo)->migid,
                            BASE_ANS_KEY_STR
            );

            if(ret != SBCOK) {
                //
                // Abnromal state added at 20251021
                //
                bt_proc->bootst = SB_PROC_ST_ABNRAM;
                SBC_BootKeyModeChange(BOOT_MODE_FACTORY, KEY_MODE_UPDATE, priv);
                goto errdone;
            }



            ret = SBC_BootKeyModeChange(BOOT_MODE_NORMAL, KEY_MODE_NORMAL, priv);
            break;
        default:
            eprint("Not support this key mode in Recovery Boot");
            goto errdone;
        }

        break;
    case SB_PROC_ST_ABNRAM:
        dprint("Boot is Abnormal in Recovery Mode ");
        // later need to create the New API
        if(bt_proc->km != KEY_MODE_UPDATE) {
            eprint("Not support this key mode in Recovery Boot");
            goto errdone;
        }
        ret = SBC_BootKeyModeChange(BOOT_MODE_FACTORY, KEY_MODE_UPDATE, priv);
        break;
    default:
        eprint("Unknown Secure Boot status");
        goto errdone;
    }

    if(ret != SBCOK) {
        eprint("Boot and Key mode change fail");
        goto errdone;
    }



errdone:

    SBC_RebootSystem();
    return;
}

SBCStatus _update_protected_software(VOID *priv)
{
    SBCStatus ret = SBCOK;
    UINT8 secret_key[SBC_OSID_KEY_LEN] = {0, };
    boot_proc_t *bp = (boot_proc_t *)priv;

    //VOID *tmp = NULL;
    SBC_RET_VALIDATE_ERRCODEMSG((bp != NULL), SBCNULLP, "Boot Proc Nill");

    // Compute the Update Secret Key
   // SBC_CONTAINER_OF(priv, )
    ret = SBC_HashCompute(NULL, 
                          ((atp_ident_t *)bp->keyinfo)->migid,
                          SBC_OSID_KEY_LEN,
                          secret_key);
    SBC_RET_VALIDATE_ERRCODEMSG((ret == SBCOK), ret, "Secret key create fail for Migration Key");
    
     

    return ret;
errdone:

    return ret;


}


static void _update_reset_check_and_behavior(VOID *priv)
{
    boot_proc_t *bp = (boot_proc_t *)priv;
    dprint("Key mode : %d", bp->km);
    switch(bp->km) {
    case KEY_MODE_NORMAL:
        //dprint("Boot State : %d", bp->bootst);
        switch(bp->bootst) {
        case SB_PROC_ST_NRMA:
            //dprint();
            dprint("Boot is Normal ");
            // bug fixed at 20250814 
            // bug fixed at 20251019 - Normal to Recovery in Update
            SBC_BootKeyModeChange(BOOT_MODE_RECOVERY, KEY_MODE_NORMAL, priv);
            break;
        case SB_PROC_ST_ABNRAM:
            dprint("Boot is AbNormal");
            if(bp->pvs_sw_bnk) {
                //dprint();
                // if existense the previously firmware 
                SBC_BootKeyModeChange(BOOT_MODE_RECOVERY, KEY_MODE_UPDATE, priv);
            }
            else {
                //dprint();
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
    //dprint();


    return;
}

static VOID _handling_sb_process_for_bm_normal(VOID *priv)
{
    boot_proc_t *p = (boot_proc_t *)priv;

    switch(p->bootst) {
    case SB_PROC_ST_NRMA:
        SBC_BootKeyModeChange(BOOT_MODE_NORMAL, KEY_MODE_NORMAL, priv);
        break;
    case SB_PROC_ST_ABNRAM:
        if(p->pvs_sw_bnk) {
            SBC_BootKeyModeChange(BOOT_MODE_RECOVERY, KEY_MODE_BOOT, priv);
        }
        else {
            SBC_BootKeyModeChange(BOOT_MODE_FACTORY, KEY_MODE_BOOT, priv);
        }

        //
        // System Reboot 
        //
        SBC_RebootSystem();

        break;
    default:
        eprint("Unknown Boot State");
        break;
    }
}

VOID SBC_ResetScenario(VOID *priv)
{
    boot_proc_t *bp = (boot_proc_t *)priv;
    //dprint("Boot Mode : %d", bp->bm);
    switch(bp->bm) {
    case BOOT_MODE_NORMAL:
        dprint("Boot Mode BOOT_MODE_NORMAL in Reset Scenario");
        //
        // Handlnig the Abnomral operation
        //
        _handling_sb_process_for_bm_normal(priv);

        

        break;
    case BOOT_MODE_UPDATE:
        {   
             dprint("Boot Mode BOOT_MODE_UPDATE");
            //dprint();
            _update_reset_check_and_behavior(priv);
        }
        break;
    case BOOT_MODE_FACTORY:
        dprint("Boot Mode BOOT_MODE_FACTORY");
        break;
    case BOOT_MODE_RECOVERY:
        dprint("Boot Mode BOOT_MODE_RECOVERY");
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

        ret = SBC_DiceIDKeyVerify((VOID *)bp);
        SBC_RET_VALIDATE_ERRCODEMSG((ret == SBCOK), ret, "Certificate ID Verify Fail");


        

        // TODO : Baseanswer verify
        ret = SBC_BaseAnswerValidate(bp->blkhnd,
                                     ((LV_t *)bp->baseansr)->value,
                                     SBC_BASE_ANSR_LEN,
                                     ((atp_ident_t *)bp->keyinfo)->osid,
                                     SBC_OSID_KEY_LEN,
                                     TRUE);
        if(ret != SBCOK) {
            //TODO : SysLog
            //bp->bootst = SB_PROC_ST_ABNRAM;
            goto errdone;
        }
        else {
            sbc_err_sysprn(SBC_LOG_CMN_PRIO_INFO, 2,
                 SYS_LOG_HOST_BOOT,
                 SYS_LOG_APP_NAME,
                 SYS_LOG_CSC_NAME,
                 8,
                 SYS_LOG_EVT_VALDIATION,
                 L"SBC_Integrity_All boot components passed signature verification \n");

        }

//      if(bp->bootst == SB_PROC_ST_ABNRAM) {
//
//          // In case of the Boot Mode is Normal and Boot State is Abnormal.
//          // It MUST remove the comment in the release
//          //_sbc_abnormal_processing(priv);
//
//              // TODO : error processing
//          SBC_RebootSystem();
//      }

        if(((rawprt_hdr_t *)bp->rawprt_hdr)->rcvmode) {
            // It is boot-up from Recovery
            // FWID and OSID Certificate Verify
        }
        else {
            // FWID and OSID key-pair verify

        }

        break;
    case BOOT_MODE_RECOVERY:
        //dprint("Block  I/O Handle : 0x%lx",bp->blkhnd);
        SBC_RecoveryBootProcessing(priv);
        break;

    case BOOT_MODE_UPDATE:
        ret = SBC_UpdateBootPorcsesing(priv);


        //dprint();
        break;
    case BOOT_MODE_FACTORY:
        //
        // Added at 20251019 - In factory mode, boot is not normal
        // System need to begin shutdown 
        //
        if(bp->bootst == SB_PROC_ST_ABNRAM) {
            SBC_ShutdownSystem();
        }
        
        break;
    default:
      goto errdone;
      //break;
    }

    


errdone:

    if(ret != SBCOK) {
        eprint("Boot is AbNormal");
        bp->bootst = SB_PROC_ST_ABNRAM;
    }
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
