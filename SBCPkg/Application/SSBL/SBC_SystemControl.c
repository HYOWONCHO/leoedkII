/********************************************************************************
 * Copyright (C) 2024 by Security Platform Inc.                                 *
 * This file is part of the SBC Project.                                        *
 *                                                                              *
 * This software contains confidential and proprietary information of           *
 * Security Platform Inc. Unauthorized reproduction, distribution, or           *
 * disclosure of this software, in whole or in part, is strictly prohibited.    *
 ********************************************************************************/

/**
 * @file SBC_SystemControl.c
 * @brief Handling of the System state and decided the System booting
 *        proceddure
 *
 * @author LEON
 * @version 1.0
 * @date 2025-10-31
 *
 * @copyright (c) 2025 Security Platform Inc. All rights
 *            reserved.
 *
 * @details
 * This file implements the System Reset, Normal/Ab-normal of System Booting
 * procedure, Reset and Shutdown decides.
 *
 */

#include <Uefi.h>
#include <Library/UefiRuntimeServicesTableLib.h>
#include <Library/BaseLib.h>
#include <Library/ResetSystemLib.h>
#include <Library/BaseMemoryLib.h>
#include <Library/MemoryAllocationLib.h>
#include <Library/PrintLib.h>

#include "SBC_SystemControl.h"
#include "SBC_AntiTampering.h"
#include "SBC_Hashing.h"
#include "SBC_CryptAES.h"
#include "SBC_EccSignVerify.h"

#include "SBC_BootProc.h"
#include "SBC_FileCtrl.h"
#include "SBC_Kdf.h"
#include "SBC_ProtectedSW.h"

#ifdef _SBC_TPM_
#include "SBC_Nvram.h"
#endif

#include "SBC_Config.h"

static UINT32 stay_recovery_flag = 0;

//EFI_GUID g_sbc_guid  = {0x1F3F7E80, 0xDB6B, 0x93FA, {0x9E, 0x61, 0x4C, 0x31, 0x3D, 0x3A}};
#ifdef _ALL_PASS_
extern SBCStatus SBC_GRUB_LoadAndStart(EFI_HANDLE ImageHandle);
#endif

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

    if(bp->bm == BOOT_MODE_RECOVERY || hdr->rcvmode == 1) {
        hdr->rcvmode = 1;
    }
    else {
        hdr->rcvmode = 0;
    }

    //dprint();
    SBC_RET_VALIDATE_ERRCODEMSG((bp->blkhnd != NULL), SBCNULLP, "Raw Partition Block IO Handle Nill");

    //dprint();
    CopyMem(wrbuf, (void *)hdr, sizeof *hdr);
    
    // Boot Mode write
    ret = SBC_RawPrtBlockWrite(bp->blkhnd,(UINT8 *)wrbuf, 512,0);
    SBC_RET_VALIDATE_ERRCODEMSG((ret == SBCOK), ret, "Boot and Key mode write fail");

    sbc_err_sysprn(SBC_LOG_CMN_PRIO_ERR, 2,
                 SYS_LOG_HOST_BOOT,
                 SYS_LOG_APP_NAME,
                 SYS_LOG_CSC_NAME,
                 0,
                 SYS_LOG_EVT_DETECTION,
                 L"SFR-Vendor-SP Success to change the Boot and Key Mode \n");

        //goto errdone;

    SBC_mem_print_bin("Boot Mode Change", wrbuf, 128);
errdone:

    if(ret != SBCOK) {

        sbc_err_sysprn(SBC_LOG_CMN_PRIO_ERR, 2,
                     SYS_LOG_HOST_BOOT,
                     SYS_LOG_APP_NAME,
                     SYS_LOG_CSC_NAME,
                     0,
                     SYS_LOG_EVT_DETECTION,
                     L"SFR-Vendor-SP Failed to change the Boot and Key Mode \n");

        //goto errdone;
    }
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
#ifdef _HANDLE_PROTSW_

//static UINTN _get_firmware_bank_addrses(UINTN bnkid)
//{
//    UINTN offset = 0ULL;
//
//    switch(bnkid) {
//    case 1:
//        offset = BOOT_SECTOR1_OFS;
//        break;
//    case 2:
//        offset = BOOT_SECTOR2_OFS;
//        break;
//    default:
//        eprint("Unknown Firmware Bank ID");
//        break;
//    }
//
//    return offset;
//}
extern SBCStatus  SBC_DiceKeysGenOld(EFI_HANDLE ImageHandle, VOID *p,UINTN normbank, UINTN bm);

extern SBCStatus SBC_GenFWIDOld(EFI_HANDLE *h_image, UINT8 *devid, UINT8 *fwid, UINTN normbank, UINTN bm)
;
extern SBCStatus  SBC_DiceKeysGen(EFI_HANDLE ImageHandle, VOID *p,UINTN normbank, UINTN bm);


SBCStatus SBC_GetOSIDFromRawPrt(VOID *priv, UINT8 *decbuf)
{
    SBCStatus ret = SBCOK;
    boot_proc_t *p = (boot_proc_t *)priv;
    UINTN ofs = 0;
    UINTN enclen = 0;
    UINT8 iv[12] = {0,};
    UINT8 tag[16] = {0,};
    UINT8 encbuf[64] = {0, };
    UINT8 shared_secret[SBC_AT_RP_KEY_LEN] = {0, };
    CHAR16 err_out_key_val[128] = {0, };

    SBC_AESContext aesctx;
    SBC_AESGcmCtx  ctx;

    ret = SBC_DeviceSecuirtyKeyCreate(shared_secret);
    if( ret != SBCOK ) {
        sbc_err_sysprn(SBC_LOG_CMN_PRIO_ERR, 1,
                     SYS_LOG_HOST_BOOT,
                     SYS_LOG_APP_NAME,
                     SYS_LOG_CSC_NAME,
                     8,
                     SYS_LOG_EVT_VALDIATION,
                     L"SBC_RawFS_Key Creation Fail");
        goto errdone;
    }

    ofs = SYS_CONF_START_OFS | SYS_CONF_OSID_OFS;
    ret = SBC_RawAlignedReadBlockIO(p->blkhnd, 
                               ofs,
                                SBC_RAW_PRTHDR_LEN_OFS,
                               &enclen
                               );

    if(ret != SBCOK) {
        eprint("Get OSID Len read fail");
        goto errdone;
    }

    ofs += SBC_RAW_PRTHDR_LEN_OFS;
    ret = SBC_RawAlignedReadBlockIO(p->blkhnd,
                                    ofs,
                                    enclen,
                                    encbuf);
    ofs += enclen;
    ret  = SBC_RawAlignedReadBlockIO(p->blkhnd, 
                                 ofs,
                                 SBC_AT_RP_IV_LEN,
                                 iv);

    ofs += SBC_AT_RP_IV_LEN;
    ret  = SBC_RawAlignedReadBlockIO(p->blkhnd, 
                                 ofs,
                                 SBC_AT_RP_TAG_LEN,
                                 tag);

    ctx.msg.value = (void *)encbuf;
    ctx.out.value = (void *)decbuf;
    ctx.msg.length = ctx.out.length = enclen;

    aesctx.gcm = &ctx;
    aesctx.algoid = SBC_CIPHER_AES_GCM;

    //dprint("");
    SBC_AESGcmSetContext((void *)aesctx.gcm, 
                     (void *)shared_secret, 
                     (void *)iv, 
                     (void *)tag);

    if (SBC_AESGcmDecrypt(&aesctx) != SBCOK) {
        SBC_LogHexToStrChar16(shared_secret, 32, err_out_key_val, sizeof(err_out_key_val)/sizeof(err_out_key_val[0]),  FALSE, 0);
        UnicodeSPrint(mrgmsg,  sizeof mrgmsg, L"SBC_VENDOR_SP Failed to decrypt (%s) \n", err_out_key_val);
        sbc_err_sysprn(SBC_LOG_CMN_PRIO_ERR, 2,
                 SYS_LOG_HOST_BOOT,
                 SYS_LOG_APP_NAME,
                 SYS_LOG_CSC_NAME,
                 5,
                 SYS_LOG_EVT_DETECTION,
                 mrgmsg);
        ret = SBCENCFAIL;
        goto errdone;
    }
    ret = SBCOK;

errdone:

    return ret;
}
static SBCStatus _compute_previously_osid(VOID *handle, VOID *old)
{
    SBCStatus ret = SBCOK;
    //UINTN fw_ofs = 0ULL;

    boot_proc_t *bp = (boot_proc_t *)handle;

#if 0
    atp_ident_t atpid;

    dprint("Compute the OLD OSID ---");
    ZeroMem((void *)&atpid, sizeof atpid);
    ret = SBC_DiceKeysGenOld(bp->ldhndl, &atpid, bp->curr_sw_bnk, bp->bm);
    if (ret != SBCOK) {
        sbc_err_sysprn(SBC_LOG_CMN_PRIO_ERR, 2,
             SYS_LOG_HOST_BOOT,
             SYS_LOG_APP_NAME,
             SYS_LOG_CSC_NAME,
             1,
             SYS_LOG_EVT_VALDIATION,
             L"SBC_Dice_Key HW&SW Base Old OSID Key Creation Fail");
       
        bp->bootst = SB_PROC_ST_ABNRAM;
        goto errdone;
    }

    CopyMem((void *)old, (const void *)atpid.osid, SBC_AT_RP_KEY_LEN);
#else
    dprint("Compute the OLD OSID !!!!---");
    ret = SBC_GetOSIDFromRawPrt((VOID *)bp, old);
    if (ret != SBCOK) {
        sbc_err_sysprn(SBC_LOG_CMN_PRIO_ERR, 2,
             SYS_LOG_HOST_BOOT,
             SYS_LOG_APP_NAME,
             SYS_LOG_CSC_NAME,
             1,
             SYS_LOG_EVT_VALDIATION,
             L"SBC_Dice_Key HW&SW Base Old OSID Key Creation Fail");
       
        bp->bootst = SB_PROC_ST_ABNRAM;
        goto errdone;
    }
#endif

    
    SBC_mem_print_bin("OLD OSID", old, 32);
errdone:

    return ret;

}


static SBCStatus _proetcted_sw_re_enc_dec(VOID *handle)
{
    SBCStatus ret = SBCOK;
    boot_proc_t *bp = (boot_proc_t *)handle;

    UINT8 deckey[SBC_AT_RP_KEY_LEN] = {0, };
    UINT8 enckey[SBC_AT_RP_KEY_LEN] = {0, };
    UINT8 old_osid[SBC_AT_RP_KEY_LEN] = {0, };

    VOID *decrypt_key = NULL;
    VOID *encrypt_key = NULL;

    //
    // Added by Leon at 25-11-04
    // Handling when KEY_BOOT_MODE
    //
    if(bp->km == KEY_MODE_BOOT) {
        //system_key = ((atp_ident_t *)bp->keyinfo)->osid;
        // compute the previously OSID 
        ret = _compute_previously_osid((VOID *)bp, old_osid);
        SBC_RET_VALIDATE_ERRCODEMSG((ret == SBCOK), ret, "Fail to the OLD OSID generating");

        decrypt_key = (VOID *)old_osid;
    }
    else {
        decrypt_key = ((atp_ident_t *)bp->keyinfo)->migid;
        
    }

    encrypt_key = ((atp_ident_t *)bp->keyinfo)->osid;



    SBC_mem_print_bin("decrypt key", (UINT8 *)decrypt_key, SBC_AT_RP_KEY_LEN);
    ret = SBC_HashCompute(NULL, 
                          decrypt_key,
                          SBC_AT_RP_KEY_LEN,
                          deckey);
    SBC_RET_VALIDATE_ERRCODEMSG(!(ret != SBCOK), ret, 
                                "Failed to Dec secret key Screation");

    SBC_mem_print_bin("hash decrypt key", (UINT8 *)deckey, SBC_AT_RP_KEY_LEN);

    SBC_mem_print_bin("encrypt key", (UINT8 *)encrypt_key, SBC_AT_RP_KEY_LEN);
    ret = SBC_HashCompute(NULL, 
                          encrypt_key,
                          SBC_AT_RP_KEY_LEN,
                          enckey);
    SBC_RET_VALIDATE_ERRCODEMSG(!(ret != SBCOK), ret, 
                                "Failed to Enc secret key creation");



    SBC_mem_print_bin("hash encrypt key", (UINT8 *)enckey, SBC_AT_RP_KEY_LEN);

    ret = SBC_ProtSWDecrypt((VOID *)bp, 
                            enckey,
                            deckey,
                            NULL, NULL);

    if(ret != SBCOK) {
        sbc_err_sysprn(SBC_LOG_CMN_PRIO_INFO, 2,
               SYS_LOG_HOST_BOOT,
               SYS_LOG_APP_NAME,
               SYS_LOG_CSC_NAME,
               3,
               SYS_LOG_EVT_DETECTION,
               L"SBC_Integrity_Protected SW integrity check failed");

        goto errdone;
    }

    sbc_err_sysprn(SBC_LOG_CMN_PRIO_INFO, 2,
               SYS_LOG_HOST_BOOT,
               SYS_LOG_APP_NAME,
               SYS_LOG_CSC_NAME,
               3,
               SYS_LOG_EVT_VALDIATION,
               L"SBC_Integrity_Protected SW successfully decryped using OSID-derived key");


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
#endif
static SBCStatus _update_behavior_for_km(void *priv)
{
    BOOLEAN skip_protsw = FALSE;
    SBCStatus ret = SBCOK;
    boot_proc_t *bp = (boot_proc_t *)priv;

#ifdef _TEST_ERROR_SET_    
        if (NvramErr_IsTrue(ERR_PREV_FW_NOTEXIST)) {
            sbc_err_sysprn(SBC_LOG_CMN_PRIO_INFO, 2,
                 SYS_LOG_HOST_BOOT,
                 SYS_LOG_APP_NAME,
                 SYS_LOG_CSC_NAME,
                 0,
                 L"Validation",
                 L"SBC_VENDOR_SP Previously Firmware Not Exists \n");

            //ret = SBCFAIL;

            bp->pvs_sw_bnk = 0;
            ret = SBCFAIL;
            goto errdone;
        }
#endif

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


#ifdef _HANDLE_PROTSW_
        ret =  _proetcted_sw_re_enc_dec((void *)bp);
        if(ret != SBCOK) {
            skip_protsw = TRUE;
            eprint("Detection _proetcted_sw_re_enc_dec ");
            goto errdone;
        }

        skip_protsw = TRUE;
#endif
        ret = SBC_BootKeyModeChange(BOOT_MODE_NORMAL, KEY_MODE_NORMAL, priv);
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
        sbc_err_sysprn(SBC_LOG_CMN_PRIO_INFO, 2,
             SYS_LOG_HOST_BOOT,
             SYS_LOG_APP_NAME,
             SYS_LOG_CSC_NAME,
             0,
             L"Validation",
             L"SBC_VENDOR_SP Update Mode operation fail \n");

        sbc_err_sysprn(SBC_LOG_CMN_PRIO_INFO, 2,
             SYS_LOG_HOST_BOOT,
             SYS_LOG_APP_NAME,
             SYS_LOG_CSC_NAME,
             0,
             L"Validation",
             L"SBC_VENDOR_SP Firmware Restore Starting \n");


        if(_check_prev_fw(bp->pvs_sw_bnk) == TRUE) {
            // Previously exist in Raw Part.
            SBC_BootKeyModeChange(BOOT_MODE_RECOVERY,
                                  KEY_MODE_UPDATE,
                                  priv);

            UINTN bytes_read = 0ULL;
            UINTN dst_offset = 0ULL;
            UINTN src_offset = 0ULL;
            EFI_STATUS Status = EFI_SUCCESS;
            src_offset = (BOOT_SECTOR1_OFS + BOOT_SSBL_OFS + ((bp->pvs_sw_bnk -1) << SBC_BOOTFW_BKN_OFS));
            dst_offset = (BOOT_SECTOR1_OFS + BOOT_SSBL_OFS + ((bp->curr_sw_bnk -1) << SBC_BOOTFW_BKN_OFS));
            dprint("Restoring Firmware Source Offset :0x%lx", src_offset);
            dprint("Restoring Firmware Destnation Offset :0x%lx", dst_offset);

            Status = SBC_CopyBlockReadAndBlockWrite(bp->blkhnd, src_offset, dst_offset, (UINT32 *)&bytes_read);

            if(EFI_ERROR(Status)) {
                eprint("Restoring FW Fail (%r)", Status);
                sbc_err_sysprn(SBC_LOG_CMN_PRIO_INFO, 2,
                     SYS_LOG_HOST_BOOT,
                     SYS_LOG_APP_NAME,
                     SYS_LOG_CSC_NAME,
                     0,
                     L"Validation",
                     L"SBC_VENDOR_SP Previously Firmware Restore Fail \n");
                ret = SBCFAIL;
                goto errdone2;
            }

            sbc_err_sysprn(SBC_LOG_CMN_PRIO_INFO, 2,
                     SYS_LOG_HOST_BOOT,
                     SYS_LOG_APP_NAME,
                     SYS_LOG_CSC_NAME,
                     0,
                     L"Validation",
                     L"SBC_VENDOR_SP Previously Firmware Restore Success \n");

#ifdef _HANDLE_PROTSW_
            if(skip_protsw != TRUE) {
                ret =  _proetcted_sw_re_enc_dec((void *)bp);
                if(ret != SBCOK) {
                    //goto errdone;
                    ret = SBCFAIL;
                }
            }
#endif

            ret = SBCFAIL;

        }
        else {

            sbc_err_sysprn(SBC_LOG_CMN_PRIO_INFO, 2,
                 SYS_LOG_HOST_BOOT,
                 SYS_LOG_APP_NAME,
                 SYS_LOG_CSC_NAME,
                 0,
                 L"Validation",
                 L"SBC_VENDOR_SP Previously Firmware Not Exists, Restoring Start \n");

            SBC_BootKeyModeChange(BOOT_MODE_FACTORY,
                                  KEY_MODE_UPDATE,
                                  priv);


            UINTN bytes_read = 0ULL;
            UINTN dst_offset = 0ULL;
            UINTN src_offset = 0ULL;
            EFI_STATUS Status = EFI_SUCCESS;
            src_offset = (BOOT_SECTOR3_OFS + BOOT_SSBL_OFS);
            dst_offset = (BOOT_SECTOR1_OFS + BOOT_SSBL_OFS + ((bp->curr_sw_bnk -1) << SBC_BOOTFW_BKN_OFS));
            dprint("Restoring Firmware Source Offset :0x%lx", src_offset);
            dprint("Restoring Firmware Destnation Offset :0x%lx", dst_offset);

            Status = SBC_CopyBlockReadAndBlockWrite(bp->blkhnd, src_offset, dst_offset, (UINT32 *)&bytes_read);

            if(EFI_ERROR(Status)) {
                eprint("Restoring FW Fail (%r)", Status);
                sbc_err_sysprn(SBC_LOG_CMN_PRIO_INFO, 2,
                     SYS_LOG_HOST_BOOT,
                     SYS_LOG_APP_NAME,
                     SYS_LOG_CSC_NAME,
                     0,
                     L"Validation",
                     L"SBC_VENDOR_SP Factory Firmware Restore Fail \n");
                ret = SBCFAIL;
                goto errdone2;
            }

            sbc_err_sysprn(SBC_LOG_CMN_PRIO_INFO, 2,
                     SYS_LOG_HOST_BOOT,
                     SYS_LOG_APP_NAME,
                     SYS_LOG_CSC_NAME,
                     0,
                     L"Validation",
                     L"SBC_VENDOR_SP Factory Firmware Restore Success \n");

#ifdef _HANDLE_PROTSW_
            if(skip_protsw != TRUE) {
                ret =  _proetcted_sw_re_enc_dec((void *)bp);
                if(ret != SBCOK) {
                    eprint("Detection _proetcted_sw_re_enc_dec ");
                    //goto errdone;
                    ret = SBCFAIL;
                }
            }
#endif
        }

        ret = SBCFAIL;
    }
    else {
        sbc_err_sysprn(SBC_LOG_CMN_PRIO_INFO, 2,
             SYS_LOG_HOST_BOOT,
             SYS_LOG_APP_NAME,
             SYS_LOG_CSC_NAME,
             0,
             L"Validation",
             L"SBC_VENDOR_SP Update Mode operation done \n");
    }
errdone2:
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

    UINT8 encbuf[SBC_AT_SYSCONF_CRT_MAX] = {0, };

    at_key_t fw_key;
    at_key_t os_key;
    boot_proc_t *bp = (boot_proc_t *)priv;
    UINT32 rdlen = 0;

    UINTN lba = 0;
    [[maybe_unused]] rawprt_hdr_t h_rawptrheader;


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
                 SYS_LOG_EVT_DETECTION,
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
                 SYS_LOG_EVT_DETECTION,
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
//  ctx.out.value = encbuf;
//  ctx.out.length = sizeof encbuf;
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

    dprint("Firmware Key Buffer Size : %d", ctx.out.length);
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
    cpy_offset = SYS_CONF_FWID_CRT_OFS;
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
    dprint("OSID Key Buffer Size : %d", ctx.out.length);
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



//    id_len = 512;
//    ret = SBC_RawPrtReadBlock(bp->blkhnd,
//                             buf,
//                              &id_len,
//                              0);
//    if(ret != SBCOK) {
//        eprint("Block Read Fail for Raw-Partition Header");
//        goto errdone;
//    }
//
//    CopyMem((void *)&h_rawptrheader, buf, 128);
//
//    h_rawptrheader.rcvmode = 1;
//
//    CopyMem((void *)buf,
//            (void *)&h_rawptrheader,
//            sizeof h_rawptrheader);
//
////  SBC_mem_print_bin("WR Recovery Bits", (UINT8 *)buf, 128);
//
//    ret = SBC_RawPrtBlockWrite(bp->blkhnd,
//                         buf,
//                         id_len,
//                         0);
//    if(ret != SBCOK) {
//        eprint("Block Write Fail for Raw-Partition Header");
//        goto errdone;
//    }

//  ret = SBC_RawPrtReadBlock(bp->blkhnd,
//                           buf,
//                            &id_len,
//                            0);
//  SBC_mem_print_bin("RD Recovery Bits", (UINT8 *)buf, 128);
errdone:

    if(buf != NULL) {
        FreePool(buf);
        buf = NULL;
    }

    return ret;

}

SBCStatus  SBC_DiceKeysReGen(EFI_HANDLE ImageHandle, VOID *p,UINTN normbank, UINTN bm)
{
    SBCStatus ret = SBCOK;
    atp_ident_t *h = NULL;

    h = (atp_ident_t *)p;

    ret = SBC_GenDeviceID(h->devid);
    if (ret != SBCOK) {
        dprint("Device ID generate fail \n");
        goto errdone;
    }

    //SBC_mem_print_bin("Device ID", h->devid, sizeof h->devid);SBC_mem_print_bin("Device ID", h->devid, sizeof h->devid);




    ret = SBC_GenFWID(ImageHandle, h->devid, h->fwid, normbank, bm);
    if (ret != SBCOK) {
        dprint("FW ID generate fail \n");
        goto errdone;
    }

    //SBC_mem_print_bin("Firmware ID", h->fwid, sizeof h->fwid);

    ret = SBC_GenOSID(ImageHandle,  h->fwid, h->osid);
    if (ret != SBCOK) {
        dprint("FW ID generate fail \n");
        goto errdone;
    }

    //SBC_mem_print_bin("Firmware ID", h->fwid, sizeof h->fwid);
    ret = SBCOK;

errdone:
    return ret;

}


void  SBC_RecoveryBootProcessing(VOID *priv)
{
    SBCStatus ret = SBCOK;
    //sb_rcv_proc_t *p = NULL;
    boot_proc_t   *bt_proc = NULL; // BOot process
    atp_ident_t new_dice_id;

    // bug -->
    //p = (sb_rcv_proc_t *)priv;
    bt_proc = (boot_proc_t *)priv;

    dprint("---> Enter the Recovery Mode");

    //p->baseans  = bt_porc

    // Boot Mode is Recovery and Boot Status is abnormal 
    // Boot Mode is change from Recovery to Factory
    // Than, Key mode is Boot
    if(bt_proc->bootst == SB_PROC_ST_ABNRAM) {
        //SBC_BootKeyModeChange(BOOT_MODE_FACTORY, bt_proc->km, priv);
        SBC_BootKeyModeChange(BOOT_MODE_FACTORY, KEY_MODE_NORMAL, priv);
        sbc_err_sysprn(SBC_LOG_CMN_PRIO_INFO, 2,
             SYS_LOG_HOST_BOOT,
             SYS_LOG_APP_NAME,
             SYS_LOG_CSC_NAME,
             1,
             SYS_LOG_EVT_DETECTION,
             L"SBC_VENDOR_SP System Reset - Recovery Boot State Ab-normal");
     
#ifndef _ALL_PASS_
        SBC_RebootSystem();
        return;
#else
        SBC_GRUB_LoadAndStart(bt_proc->ldhndl);
#endif
    }

//    if(_check_prev_fw(bt_proc->pvs_sw_bnk) != TRUE) {
//        SBC_BootKeyModeChange(BOOT_MODE_FACTORY, KEY_MODE_BOOT, priv);
//        SBC_RebootSystem();
//        return;
////      eprint("Previously Boot Firmware not existense");
////      // System Shutdown
////      goto errdone;
//
//    }


    // Create the OSID

    // TODO : 
    // A. BaseAnswer load from System Setting block of Block IO 
    // B. Decrypt the BaseAnswer using Migration Key
    // C. Re-encrypt the decrypted baseanswer using OSID
    // D. Re-write the baseanswer in System Setting block of Block IO

    ZeroMem(&new_dice_id, sizeof new_dice_id);

    dprint("---> New Dice Key Create ~~~");
    sbc_err_sysprn(SBC_LOG_CMN_PRIO_INFO, 2,
             SYS_LOG_HOST_BOOT,
             SYS_LOG_APP_NAME,
             SYS_LOG_CSC_NAME,
             1,
             SYS_LOG_EVT_VALDIATION,
             L"SBC_Dice_Key New Create");

    ret = SBC_DiceKeysReGen(bt_proc->ldhndl, 
                      &new_dice_id, 
                      bt_proc->curr_sw_bnk, 
                      bt_proc->bm);

    if(ret != SBCOK) {
        eprint("On Recovery Mode, New Dice Key fail !!!");
        sbc_err_sysprn(SBC_LOG_CMN_PRIO_ERR, 2,
             SYS_LOG_HOST_BOOT,
             SYS_LOG_APP_NAME,
             SYS_LOG_CSC_NAME,
             1,
             SYS_LOG_EVT_VALDIATION,
             L"SBC_Dice_Key HW&SW Base New Dice Key Creation Fail");
        bt_proc->bootst = SB_PROC_ST_ABNRAM;
    }

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
                            new_dice_id.osid,
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

            SBC_mem_print_bin("Recovery Base Answer Encrypt Key",
                              new_dice_id.osid, BASE_ANS_KEY_STR);

            ret = _store_fw_os_keypair_store(priv,
                               new_dice_id.fwid,
                               new_dice_id.osid);

            if(ret != SBCOK) {
                eprint("_store_fw_os_keypair_store fail, that is, Abnormal");
                bt_proc->bootst = SB_PROC_ST_ABNRAM;
            }

            ret = _proetcted_sw_re_enc_dec((VOID *)bt_proc);
            if(ret != SBCOK) {
                //
                // Abnromal state added at 20251021
                //
                bt_proc->bootst = SB_PROC_ST_ABNRAM;
                SBC_BootKeyModeChange(BOOT_MODE_FACTORY, KEY_MODE_BOOT, priv);
                goto errdone;
            }

            //ret = SBC_BootKeyModeChange(BOOT_MODE_NORMAL, KEY_MODE_NORMAL, priv);

//          ret = SBC_RawPrtHdrChange(priv,
//                                    bt_proc->pvs_sw_bnk,
//                                    bt_proc->curr_sw_bnk,
//                                    0,
//                                    BOOT_MODE_NORMAL,
//                                    KEY_MODE_NORMAL);

            ret = SBC_RawPrtHdrChangeWithRecovery(priv,
                                      bt_proc->pvs_sw_bnk,
                                      bt_proc->curr_sw_bnk,
                                      0,
                                      BOOT_MODE_NORMAL,
                                      KEY_MODE_NORMAL);
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

            ret = _store_fw_os_keypair_store(priv,
                               new_dice_id.fwid,
                               new_dice_id.osid);

            if(ret != SBCOK) {
                eprint("_store_fw_os_keypair_store fail, that is, Abnormal");
                bt_proc->bootst = SB_PROC_ST_ABNRAM;
            }

            ret = _proetcted_sw_re_enc_dec((VOID *)bt_proc);
            if(ret != SBCOK) {
                //
                // Abnromal state added at 20251021
                //
                bt_proc->bootst = SB_PROC_ST_ABNRAM;
                SBC_BootKeyModeChange(BOOT_MODE_FACTORY, KEY_MODE_UPDATE, priv);
                goto errdone;
            }

//          ret = SBC_RawPrtHdrChange(priv,
//                                    bt_proc->pvs_sw_bnk,
//                                    bt_proc->curr_sw_bnk,
//                                    0,
//                                    BOOT_MODE_NORMAL,
//                                    KEY_MODE_NORMAL);

            ret = SBC_RawPrtHdrChange(priv,
                                      bt_proc->curr_sw_bnk,
                                      bt_proc->pvs_sw_bnk,
                                      1,
                                      BOOT_MODE_NORMAL,
                                      KEY_MODE_NORMAL);

            //((boot_proc_t *)priv)->prevmode = 0;
            //ret = SBC_BootKeyModeChange(BOOT_MODE_NORMAL, KEY_MODE_NORMAL, priv);
            break;
        default:
            eprint("Not support this key mode in Recovery Boot");
            ret = SBCINVPARAM;
            sbc_err_sysprn(SBC_LOG_CMN_PRIO_INFO, 2,
                         SYS_LOG_HOST_BOOT,
                         SYS_LOG_APP_NAME,
                         SYS_LOG_CSC_NAME,
                         1,
                         SYS_LOG_EVT_DETECTION,
                         L"SBC_VENDOR_SP RECOVERY BOOT STATUS - UNKNOWN KEY MODE");
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
        ret = SBCINVPARAM;
        sbc_err_sysprn(SBC_LOG_CMN_PRIO_INFO, 2,
                         SYS_LOG_HOST_BOOT,
                         SYS_LOG_APP_NAME,
                         SYS_LOG_CSC_NAME,
                         1,
                         SYS_LOG_EVT_DETECTION,
                         L"SBC_VENDOR_SP RECOVERY BOOT STATUS - UNKNOWN");

        goto errdone;
    }

    if(ret != SBCOK) {
        eprint("Boot and Key mode change fail");
        bt_proc->bootst = SB_PROC_ST_ABNRAM;
        goto errdone;
    }



errdone:

    if(bt_proc->bootst == SB_PROC_ST_ABNRAM) {
        sbc_err_sysprn(SBC_LOG_CMN_PRIO_INFO, 2,
                         SYS_LOG_HOST_BOOT,
                         SYS_LOG_APP_NAME,
                         SYS_LOG_CSC_NAME,
                         1,
                         SYS_LOG_EVT_DETECTION,
                         L"SBC_VENDOR_SP System Reset - Recovery Boot State Ab-normal");
    }
    else {
        sbc_err_sysprn(SBC_LOG_CMN_PRIO_INFO, 2,
                         SYS_LOG_HOST_BOOT,
                    SYS_LOG_APP_NAME,
                         SYS_LOG_CSC_NAME,
                         1,
                         SYS_LOG_EVT_DETECTION,
                         L"SBC_VENDOR_SP System Reset - Recovery Boot State Normal");     

    }

#ifndef _ALL_PASS_
        SBC_RebootSystem();
        return;
#else
        SBC_GRUB_LoadAndStart(bt_proc->ldhndl);
#endif
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
            // bug fixed at 20201022 - Recoveyr to Normal
            SBC_BootKeyModeChange(BOOT_MODE_NORMAL, KEY_MODE_NORMAL, priv);
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

        if(bp->bootst == SB_PROC_ST_ABNRAM) {
            sbc_err_sysprn(SBC_LOG_CMN_PRIO_INFO, 2,
                 SYS_LOG_HOST_BOOT,
                 SYS_LOG_APP_NAME,
                 SYS_LOG_CSC_NAME,
                 1,
                 SYS_LOG_EVT_DETECTION,
                 L"SBC_VENDOR_SP System Reset - Boot State Ab-normal");
        }

#ifndef _ALL_PASS_
        SBC_RebootSystem();
        return;
#else
        SBC_GRUB_LoadAndStart(bp->ldhndl);
#endif
        
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
        if(stay_recovery_flag != 1) {
            SBC_BootKeyModeChange(BOOT_MODE_NORMAL, KEY_MODE_NORMAL, priv);
        }

        stay_recovery_flag = 0;
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
        if(p->bootst == SB_PROC_ST_ABNRAM) {
            sbc_err_sysprn(SBC_LOG_CMN_PRIO_INFO, 2,
                 SYS_LOG_HOST_BOOT,
                 SYS_LOG_APP_NAME,
                 SYS_LOG_CSC_NAME,
                 1,
                 SYS_LOG_EVT_DETECTION,
                 L"SBC_VENDOR_SP System Reset - Boot State Ab-normal");
        }
#ifndef _ALL_PASS_

        sbc_err_sysprn(SBC_LOG_CMN_PRIO_INFO, 2,
                     SYS_LOG_HOST_BOOT,
                     SYS_LOG_APP_NAME,
                     SYS_LOG_CSC_NAME,
                     4,
                     SYS_LOG_EVT_DETECTION,
                     L"SBC_Integrity_Boot mode is NORMAL mode and Reboot");

        SBC_RebootSystem();
        return;
#else
        SBC_GRUB_LoadAndStart(p->ldhndl);
#endif

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
    VOID *dec_key = NULL;

    ZeroMem((VOID *)&blob, sizeof blob);
    ZeroMem((VOID *)&srp, sizeof srp);

    //boot_proc_t backup_bp;
    //atp_ident_t newid;
    //atp_ident_t oldid;

    //ZeroMem(&backup_bp, sizeof(backup_bp));

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

        if(((rawprt_hdr_t *)bp->rawprt_hdr)->rcvmode) {
            //CopyMem(&oldid,  bp->keyinfo, sizeof(atp_ident_t));

            //SBC_mem_print_bin("OLD OSID Key", oldid.osid, 32);
            dprint("Old F/W Firwmare ID and OSID gens");
            //bp->keyinfo = (void *)&newid;
            ret = SBC_DiceKeysGenOld(bp->ldhndl,
                                     bp->keyinfo,
                                     bp->curr_sw_bnk,
                                     bp->bm);

            //SBC_mem_print_bin("Regen OSID",
            //                  ((atp_ident_t *)bp->keyinfo)->osid,
            //                  32);

        }
        ret = SBC_DiceIDKeyVerify((VOID *)bp);
        SBC_RET_VALIDATE_ERRCODEMSG((ret == SBCOK), ret, "Certificate ID Verify Fail");

//      if(((rawprt_hdr_t *)bp->rawprt_hdr)->rcvmode) {
//          CopyMem(bp->keyinfo, (void *)&oldid, sizeof(atp_ident_t));
//          SBC_mem_print_bin("Recover OSID",
//                            ((atp_ident_t *)bp->keyinfo)->osid,
//                            32);
//      }


        if(!((rawprt_hdr_t *)bp->rawprt_hdr)->rcvmode) {
            //
            // Firmware is not discover from Recover Mode
            // So, it SHOULD be perform the Key Verify
            //
            dec_key = ((atp_ident_t *)bp->keyinfo)->osid;
        }
        else {

            dec_key = ((atp_ident_t *)bp->keyinfo)->migid;
        }

        if(((rawprt_hdr_t *)bp->rawprt_hdr)->rcvmode) {
            dprint("Because recovery mode, decrypot using old osid");
            dec_key = ((atp_ident_t *)bp->keyinfo)->osid;
        }

        // TODO : Baseanswer verify
        ret = SBC_BaseAnswerValidate(bp->blkhnd,
                                     ((LV_t *)bp->baseansr)->value,
                                     SBC_BASE_ANSR_LEN,
                                     dec_key,
                                     SBC_OSID_KEY_LEN,
                                     TRUE);
        if(ret != SBCOK) {
            //TODO : SysLog
            bp->bootst = SB_PROC_ST_ABNRAM;
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

        dprint("Check recovery in the Normal ( Recovery Mode : %d ) \n", bp->rcvmode);

        if ( bp->rcvmode == 1 /* && bp->prevmode == 1 */) {
            dprint(" ***** In normal, rcv mode 1 and prevmode 1, so prevmode set to 0");
            SBC_RawPrtHdrChangeWithRecovery(bp,
                                0, 0,
                                0, // prevmode is 0
                                BOOT_MODE_UNKNOWN,
                                KEY_MODE_UNKNOWN);
            stay_recovery_flag = 1;
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

        if(ret != SBCOK) {
//prevwr_err:
            sbc_err_sysprn(SBC_LOG_CMN_PRIO_INFO, 2,
                           SYS_LOG_HOST_BOOT,
                           SYS_LOG_APP_NAME,
                           SYS_LOG_CSC_NAME,
                             1,
                             SYS_LOG_EVT_DETECTION,
                             L"SBC_VENDOR_SP System Reset - Update Boot State Ab-Normal");     
        }
        else {

//          rawprt_hdr_t raw_hdr;
//          ZeroMem(&raw_hdr, sizeof raw_hdr);
//
//          ret = SBC_RawAlignedReadBlockIO(bp->blkhnd,
//                                     0x00000000,
//                                     sizeof(raw_hdr),
//                                     (VOID *)&raw_hdr);
//          if(ret != SBCOK) {
//              eprint("On Update, Raw-partition header read fail");
//              goto errdone;
//          }
//
//          raw_hdr.prevmode = 1;
//          ret = SBC_RawAlignedWriteBlockIO(bp->blkhnd,
//                                           0x00000000,
//                                           sizeof(raw_hdr),
//                                           (VOID *)&raw_hdr);
//          if(ret != SBCOK) {
//              eprint("On Update, Raw-partition header write fail");
//              goto errdone;
//          }

            sbc_err_sysprn(SBC_LOG_CMN_PRIO_INFO, 2,
                           SYS_LOG_HOST_BOOT,
                           SYS_LOG_APP_NAME,
                           SYS_LOG_CSC_NAME,
                             1,
                             SYS_LOG_EVT_DETECTION,
                             L"SBC_VENDOR_SP System Reset - Update Boot State Normal");
        }


        //dprint();
        break;
    case BOOT_MODE_FACTORY:
        //
        // Added at 20251019 - In factory mode, boot is not normal
        // System need to begin shutdown 
        //

        if(bp->bootst == SB_PROC_ST_ABNRAM) {
            goto errdone;
        }

       ret = SBC_BaseAnswerEncryptStore(
                            bp->blkhnd,
                            ((LV_t *)bp->baseansr)->value,
                            ((LV_t *)bp->baseansr)->length,
                            ((atp_ident_t *)bp->keyinfo)->osid,
                            BASE_ANS_KEY_STR
        );

       if(ret != SBCOK) {
           bp->bootst = SB_PROC_ST_ABNRAM;
           goto errdone;
       }

       ret = SBC_BootKeyModeChange(BOOT_MODE_FACTORY, KEY_MODE_NORMAL, (void *)bp);
       if (ret != SBCOK) {
           bp->bootst = SB_PROC_ST_NRMA;
           goto errdone;
       }


        
        break;
    default:
      goto errdone;
      //break;
    }

    


errdone:


    if(bp->bootst == SB_PROC_ST_ABNRAM && bp->bm == BOOT_MODE_FACTORY) {
        SBC_ShutdownSystem();
        return ret;
    }

    if(ret != SBCOK) {
        eprint("Boot is AbNormal");
        bp->bootst = SB_PROC_ST_ABNRAM;
    }
    SBC_ResetScenario(priv);
    return ret;

}



VOID SBC_RebootSystem(VOID)
{
    //Print(L"System Reset ... \n");

    sbc_err_sysprn(SBC_LOG_CMN_PRIO_INFO, 2,
         SYS_LOG_HOST_BOOT,
         SYS_LOG_APP_NAME,
         SYS_LOG_CSC_NAME,
         1,
         SYS_LOG_EVT_DETECTION,
         L"SBC_VENDOR_SP System Reboo Re-starting ");
    gRT->ResetSystem(EfiResetCold, EFI_SUCCESS, 0, NULL);
    while(TRUE) { };

}


VOID SBC_ShutdownSystem(VOID)
{
    sbc_err_sysprn(SBC_LOG_CMN_PRIO_INFO, 2,
         SYS_LOG_HOST_BOOT,
         SYS_LOG_APP_NAME,
         SYS_LOG_CSC_NAME,
         1,
         SYS_LOG_EVT_DETECTION,
         L"SBC_VENDOR_SP System Shutdown - Boot State Ab-normal");

    gRT->ResetSystem(EfiResetShutdown, EFI_SUCCESS, 0, NULL);
    while(TRUE) { };
}

void SBC_UpdateBootPres(UINT8 *pres_buf, UINT32 cur, UINT32 prev)
{
    if (!pres_buf)
        return;

    /* cur / prev has ans non value  */
    if (cur == 0 || prev == 0)
        return;

    /*
     * pres_buf structure:
     * [0] value slot     ← determined by pres_buf[1]
     * [1] tag ('C' or 'P')
     *
     * [2] value slot     ← determined by pres_buf[3]
     * [3] tag ('C' or 'P')
     */
    for (UINT32 i = 0; i < 2; i++) {
        UINT32 v = i * 2;
        UINT32 t = v + 1;
        CHAR8 tag = pres_buf[t];

        if (tag == 'C') {
            pres_buf[v] = cur;
        } else if (tag == 'P') {
            pres_buf[v] = prev;
        }
    }
}

SBCStatus SBC_RawPrtHdrChange(
    VOID *handle, 
    UINT32 cur, 
    UINT32 prev, 
    UINT32 prevmode, 
    UINT32 bm, 
    UINT32 km)
{
    SBCStatus ret = SBCOK;
    [[maybe_unused]]EFI_STATUS retval = EFI_SUCCESS;
    boot_proc_t *b_proc = (boot_proc_t *)handle;
    rawprt_hdr_t rawhdr;
    UINT8 *pres_buf;


    ZeroMem(&rawhdr, sizeof(rawhdr));;

    ret = SBC_RawAlignedReadBlockIO(b_proc->blkhnd,
                                    0x0,
                                    sizeof rawhdr,
                                    (void *)&rawhdr);
    if (ret != SBCOK) {
        eprint("SBC_RawAlignedReadBlockIO 0x%lu read fail", 0x0);
        goto errdone;
    }

    dprint("Boot Header Read ===>");
    SBC_mem_print_bin("Raw Partition Header ", (UINT8 *)&rawhdr, sizeof rawhdr);

    rawhdr.prevmode = prevmode;
    pres_buf = rawhdr.bootpres;
    dprint("%d:%02x %d:%c %d:%02x %d:%c \n",
            0, pres_buf[0], 
            1, pres_buf[1], 
            2, pres_buf[2], 
            3, pres_buf[3]);


    /* pres_buf mapping:
     * [0] - current or previous value slot
     * [1] - prev for slot 0 ('C' or 'P')
     * [2] - current or previous value slot
     * [3] - prev for slot 2 ('C' or 'P')
     */

//  if (cur != 0 && prev != 0) {
//      if (pres_buf[1] == 'C' || pres_buf[1] == 'P') {
//          pres_buf[0] = (pres_buf[1] == 'C') ? cur : prev;
//      }
//
//      if (pres_buf[3] == 'C' || pres_buf[3] == 'P') {
//          pres_buf[2] = (pres_buf[3] == 'C') ? cur : prev;
//      }
//  }


    SBC_UpdateBootPres(pres_buf, cur, prev);

    SBC_mem_print_bin("---> Raw Partition Boot Pres ", (UINT8 *)rawhdr.bootpres, sizeof rawhdr.bootpres);

    if (bm != BOOT_MODE_UNKNOWN) {
        if(rawhdr.bootmode == BOOT_MODE_RECOVERY) {
            dprint("---> Next Firmware Start, SHOULD be power-on from Recovery Mode");
            rawhdr.rcvmode = 1;
        }
        
        rawhdr.bootmode = bm;

    }
    
    if (km != KEY_MODE_UNKNOWN) {
        rawhdr.keymode = km;
    }

    ret = SBC_RawAlignedWriteBlockIO(b_proc->blkhnd,
                                    0x0,
                                    sizeof rawhdr,
                                    (void *)&rawhdr);
    if (ret != SBCOK) {
        eprint("SBC_RawAlignedWriteBlockIO 0x%lu read fail", 0x0);
        goto errdone;
    }

    sbc_err_sysprn(SBC_LOG_CMN_PRIO_ERR, 2,
                 SYS_LOG_HOST_BOOT,
                 SYS_LOG_APP_NAME,
                 SYS_LOG_CSC_NAME,
                 0,
                 SYS_LOG_EVT_DETECTION,
                 L"SFR-Vendor-SP Success to change the "
                 L"Header informaiton of Raw-partition \n");

    ret = SBC_RawAlignedReadBlockIO(b_proc->blkhnd,
                                    0x0,
                                    sizeof rawhdr,
                                    (void *)&rawhdr);

//  dprint("---> boot mode : %d, key mode :%d, cur bank : %lu , previously bnk : %lu",
//         rawhdr.bootmode, rawhdr.keymode,
//         rawhdr., b_proc->pvs_sw_bnk);

    SBC_mem_print_bin("After write SBC_RawPrtHdrChange",
                      (UINT8 *)&rawhdr,
                      sizeof(rawhdr));
errdone:


    if (ret != SBCOK) {
        sbc_err_sysprn(SBC_LOG_CMN_PRIO_ERR, 2,
                 SYS_LOG_HOST_BOOT,
                 SYS_LOG_APP_NAME,
                 SYS_LOG_CSC_NAME,
                 0,
                 SYS_LOG_EVT_DETECTION,
                 L"SFR-Vendor-SP Failed to change the "
                 L"Header informaiton of Raw-partition \n");
    }

    return ret;
}

SBCStatus SBC_RawPrtHdrChangeWithRecovery(
    VOID *handle, 
    UINT32 cur, 
    UINT32 prev, 
    UINT32 prevmode, 
    UINT32 bm, 
    UINT32 km)
{
    SBCStatus ret = SBCOK;
    [[maybe_unused]]EFI_STATUS retval = EFI_SUCCESS;
    boot_proc_t *b_proc = (boot_proc_t *)handle;
    rawprt_hdr_t rawhdr;
    UINT8 *pres_buf;


    ZeroMem(&rawhdr, sizeof(rawhdr));;

    ret = SBC_RawAlignedReadBlockIO(b_proc->blkhnd,
                                    0x0,
                                    sizeof rawhdr,
                                    (void *)&rawhdr);
    if (ret != SBCOK) {
        eprint("SBC_RawAlignedReadBlockIO 0x%lu read fail", 0x0);
        goto errdone;
    }

    dprint("Boot Header Read ===>");
    SBC_mem_print_bin("Raw Partition Header ", (UINT8 *)&rawhdr, sizeof rawhdr);

    rawhdr.prevmode = prevmode;
    pres_buf = rawhdr.bootpres;
    dprint("%d:%02x %d:%c %d:%02x %d:%c \n",
            0, pres_buf[0], 
            1, pres_buf[1], 
            2, pres_buf[2], 
            3, pres_buf[3]);


    /* pres_buf mapping:
     * [0] - current or previous value slot
     * [1] - prev for slot 0 ('C' or 'P')
     * [2] - current or previous value slot
     * [3] - prev for slot 2 ('C' or 'P')
     */

//  if (cur != 0 && prev != 0) {
//      if (pres_buf[1] == 'C' || pres_buf[1] == 'P') {
//          pres_buf[0] = (pres_buf[1] == 'C') ? cur : prev;
//      }
//
//      if (pres_buf[3] == 'C' || pres_buf[3] == 'P') {
//          pres_buf[2] = (pres_buf[3] == 'C') ? cur : prev;
//      }
//  }


    SBC_UpdateBootPres(pres_buf, cur, prev);

    SBC_mem_print_bin("---> Raw Partition Boot Pres ", (UINT8 *)rawhdr.bootpres, sizeof rawhdr.bootpres);

    if (bm != BOOT_MODE_UNKNOWN) {
        
        if(rawhdr.bootmode == BOOT_MODE_RECOVERY) {
            dprint("---> Next Firmware Start, SHOULD be power-on from Recovery Mode");
            rawhdr.rcvmode = 1;
        }

        rawhdr.bootmode = bm;
    }
    
    if (km != KEY_MODE_UNKNOWN) {
        rawhdr.keymode = km;
    }

    rawhdr.rcvmode = 1;

    ret = SBC_RawAlignedWriteBlockIO(b_proc->blkhnd,
                                    0x0,
                                    sizeof rawhdr,
                                    (void *)&rawhdr);
    if (ret != SBCOK) {
        eprint("SBC_RawAlignedWriteBlockIO 0x%lu read fail", 0x0);
        goto errdone;
    }

    sbc_err_sysprn(SBC_LOG_CMN_PRIO_ERR, 2,
                 SYS_LOG_HOST_BOOT,
                 SYS_LOG_APP_NAME,
                 SYS_LOG_CSC_NAME,
                 0,
                 SYS_LOG_EVT_DETECTION,
                 L"SFR-Vendor-SP Success to change the "
                 L"Header informaiton of Raw-partition \n");

    ret = SBC_RawAlignedReadBlockIO(b_proc->blkhnd,
                                    0x0,
                                    sizeof rawhdr,
                                    (void *)&rawhdr);

//  dprint("---> boot mode : %d, key mode :%d, cur bank : %lu , previously bnk : %lu",
//         rawhdr.bootmode, rawhdr.keymode,
//         rawhdr., b_proc->pvs_sw_bnk);

    SBC_mem_print_bin("After write SBC_RawPrtHdrChange",
                      (UINT8 *)&rawhdr,
                      sizeof(rawhdr));
errdone:


    if (ret != SBCOK) {
        sbc_err_sysprn(SBC_LOG_CMN_PRIO_ERR, 2,
                 SYS_LOG_HOST_BOOT,
                 SYS_LOG_APP_NAME,
                 SYS_LOG_CSC_NAME,
                 0,
                 SYS_LOG_EVT_DETECTION,
                 L"SFR-Vendor-SP Failed to change the "
                 L"Header informaiton of Raw-partition \n");
    }

    return ret;
}


