/********************************************************************************
 * Copyright (C) 2024 by Security Platform Inc.                                 *
 * This file is part of the SBC Project.                                        *
 *                                                                              *
 * This software contains confidential and proprietary information of           *
 * Security Platform Inc. Unauthorized reproduction, distribution, or           *
 * disclosure of this software, in whole or in part, is strictly prohibited.    *
 ********************************************************************************/

/**
 * @file SBC_ProtectedSW.c
 * @brief Handling of the Protected Software Module 
 *
 * @author LEON
 * @version 1.0
 * @date 2025-10-31
 *
 * @copyright (c) 2025 Security Platform Inc. All rights
 *            reserved.
 *
 * @details
 * This file implements the initialization, authentication, and validation
 * procedures for the Protected Software (SW) component used in the secure boot
 * process.
 *
 * @changelog
 *
 */

#include <Library/PrintLib.h>
#include <Library/BaseMemoryLib.h>
#include <Library/MemoryAllocationLib.h>

#include "SBC_ProtectedSW.h"
#include "SBC_FileCtrl.h"
#include "SBC_BootProc.h"
#include "SBC_AntiTampering.h"
#include "SBC_CryptAES.h"
#include "SBC_Hashing.h"

#include "SBC_Config.h"

#include "SBC_Nvram.h"

extern CHAR16 mrgmsg[8192];
CHAR8 gstr_sw_name[SBC_AT_RP_SW_NAME_MAX] = {0, };
#define SBC_PROT_SYS_DATA_LEN           4


SBCStatus SBC_LoadSysFile(VOID *handle, UINTN offset, UINT8 *deckey, UINT8* data)
{

    SBCStatus ret = SBCOK;

    UINT8 iv[SBC_AT_RP_IV_LEN], tag[SBC_AT_RP_TAG_LEN];
    UINT8 enc[SBC_AT_RP_SYS_CONF_MAX_LEN];
    //UINT8 dec[SBC_AT_RP_SYS_CONF_MAX_LEN];
    UINT32 enc_len;
    boot_proc_t *p = (boot_proc_t *)handle;
    SBC_AESContext aesctx;
    SBC_AESGcmCtx  ctx;

    ret = SBC_RawAlignedReadBlockIO(p->blkhnd,
                                    offset,
                                    SBC_RAW_PRTHDR_LEN_OFS,
                                    &enc_len);
    SBC_RET_VALIDATE_ERRCODEMSG(!(ret != SBCOK), ret, "Block IO read fail");

    ret = SBC_RawAlignedReadBlockIO(p->blkhnd,
                                    offset + SBC_PROT_SYS_DATA_LEN,
                                    enc_len,
                                    enc);
    SBC_RET_VALIDATE_ERRCODEMSG(!(ret != SBCOK), ret, "Block IO read fail");

    ret = SBC_RawAlignedReadBlockIO(p->blkhnd,
                                    offset + SBC_PROT_SYS_DATA_LEN + enc_len,
                                    SBC_AT_RP_IV_LEN,
                                    iv);
    SBC_RET_VALIDATE_ERRCODEMSG(!(ret != SBCOK), ret, "Block IO read fail");

    ret = SBC_RawAlignedReadBlockIO(p->blkhnd,
                                    offset + SBC_PROT_SYS_DATA_LEN + enc_len + SBC_AT_RP_IV_LEN,
                                    SBC_AT_RP_TAG_LEN,
                                    tag);
    SBC_RET_VALIDATE_ERRCODEMSG(!(ret != SBCOK), ret, "Block IO read fail");

    //
    // Decrypt 
    //
    ctx.out.value = (void *)data;
    ctx.out.length = enc_len;
    ctx.msg.value = (void *)enc;
    ctx.msg.length = enc_len;

    aesctx.gcm = &ctx;
    aesctx.algoid = SBC_CIPHER_AES_GCM;

    SBC_AESGcmSetContext((void *)aesctx.gcm,
                         (void *)deckey,
                         (void *)iv,
                         (void *)tag);


    if( SBC_AESGcmDecrypt(&aesctx) != SBCOK ) {
        eprint("System Partition Decrypt fail");
        ret = SBCFAIL;
        goto errdone;
    }





errdone:

    return ret;

}


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

    UINTN rdlen;
    UINT8 decbuf[SBC_AT_RP_SYS_CONF_MAX_LEN] ={0, };
    UINT8 deckey[SBC_AT_RP_KEY_LEN] = {0, };

    sw_path_t *path = (sw_path_t *)decbuf;
    UINTN cnt, line, len = sizeof(sw_path_t);

    CHAR16 err_out_key_val[128] = {0,};

    ret = SBC_DeviceSecuirtyKeyCreate(deckey);
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


    //boot_proc_t *p = (boot_proc_t *)handle; 
    ret = SBC_ProtSwLoadRawPrt(handle, deckey, decbuf, &rdlen, SYS_CONF_START_OFS + SYS_CONF_SW_LIST_OFS);
    if( ret != SBCOK ) {
        SBC_LogHexToStrChar16(deckey, 32, err_out_key_val, sizeof(err_out_key_val)/sizeof(err_out_key_val[0]),  FALSE, 0);
        UnicodeSPrint(mrgmsg,  sizeof mrgmsg, L"SBC_ProtSW_Update Failed to decrypt (%s) \n", err_out_key_val);
        sbc_err_sysprn(SBC_LOG_CMN_PRIO_ERR, 2,
                 SYS_LOG_HOST_BOOT,
                 SYS_LOG_APP_NAME,
                 SYS_LOG_CSC_NAME,
                 5,
                 SYS_LOG_EVT_DETECTION,
                 mrgmsg);

        goto errdone;
    }

    line = rdlen / len;
    SBC_RET_VALIDATE_ERRCODEMSG(!(line > SBC_AT_RP_SW_PATH_MAX), SBCINVPARAM, "Invalid Len");
    dprint("protected sw count=%d\n", line);

    SBC_RET_VALIDATE_ERRCODEMSG(!(st > line), SBCINVPARAM, "Invalid parameter");
    SBC_RET_VALIDATE_ERRCODEMSG(!(sw_name == NULL), SBCNULLP, "Invalid parameter");
    SBC_RET_VALIDATE_ERRCODEMSG(!(sw_name_size > SBC_AT_RP_SW_NAME_MAX), SBCINVPARAM, "Invalid parameter");

    for(cnt = 0; cnt < st; cnt++) {
        path++;
    }

    dprint("name=%a, ver=%a, sw_node_off=%lx\n",path->name, path->ver, path->sw_node_off);
    CopyMem(sw_name, path->name, sw_name_size);

errdone:

    return ret;

}

SBCStatus SBC_WriteProtSwSize(VOID *handle, UINTN sw_off, UINTN size)
{

    SBCStatus ret = SBCOK;

    boot_proc_t *p = (boot_proc_t *)handle;

    ret = SBC_RawAlignedWriteBlockIO(p->blkhnd, sw_off, 4, (VOID *)&size);
    SBC_RET_VALIDATE_ERRCODEMSG(!(ret != SBCOK), ret, "Protected SW Size write fail");


errdone:

    return ret;


}


SBCStatus SBC_WriteProtSwNodeBlob(VOID *handle, UINTN swoff, UINT8 *blob, UINTN blob_len, UINT8 *iv, UINT8 *tag)
{
    SBCStatus ret = SBCOK;

    UINT8 *wrbuf = NULL;
    UINTN wrbuf_len = blob_len + SBC_AT_IV_LEN + SBC_AT_TAG_LEN + 4;
    UINTN cpyofs = 0;
    boot_proc_t *p = (boot_proc_t *)handle;


    wrbuf = AllocateZeroPool(wrbuf_len);
    SBC_RET_VALIDATE_ERRCODEMSG((wrbuf != NULL), SBCNULLP, "Out of Resource");

    CopyMem(&wrbuf[cpyofs], &wrbuf_len, 4);
    cpyofs += 4;

    CopyMem(&wrbuf[cpyofs], blob, blob_len);
    cpyofs += blob_len;

    CopyMem(&wrbuf[cpyofs], iv, SBC_AT_IV_LEN);
    cpyofs += SBC_AT_IV_LEN;

    CopyMem(&wrbuf[cpyofs], tag, SBC_AT_TAG_LEN);
    cpyofs += SBC_AT_TAG_LEN;


    ret = SBC_RawAlignedWriteBlockIO(p->blkhnd, swoff, wrbuf_len, (VOID *)&wrbuf_len);
    SBC_RET_VALIDATE_ERRCODEMSG(!(ret != SBCOK), ret, "Protected SW Size write fail");


errdone:

    if( wrbuf != NULL ) {
        FreePool(wrbuf);
    }

    return ret;

}

SBCStatus SBC_FindProtectedSw(VOID *handle, CHAR8 name[256], CHAR8 *ver, UINTN *sw_node_off)
{
    SBCStatus ret = SBCOK;
    UINTN  readn;
    UINT8   data[SBC_AT_RP_SYS_CONF_MAX_LEN] = {0, };
    UINT8   dec_key[SBC_AT_RP_KEY_LEN] = {0, };
    [[gnu::unused]] boot_proc_t *p = (boot_proc_t *)handle;

    sw_path_t *path = (sw_path_t *)data;
    [[maybe_unused]] UINTN len = sizeof(sw_path_t);
    UINTN cnt, line;
    sw_node_t node;
    EFI_STATUS retval = EFI_SUCCESS;

    ret = SBC_DeviceSecuirtyKeyCreate(dec_key);
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

    ret = SBC_ProtSwLoadRawPrt(handle, dec_key, data, &readn, SYS_CONF_START_OFS + SYS_CONF_SW_LIST_OFS);
    SBC_RET_VALIDATE_ERRCODEMSG(!(ret != SBCOK), ret, "System Configuration Partition Read fail");

    line = readn/len;
    dprint("protected line : %d", line);

    for(cnt = 0; cnt < line; cnt++) {
        dprint("name :%a,  path->name :%a  slot1_ver=%a, node : %lx" , 
               name, 
               path->ver,
               path->name, 
               path->sw_node_off);

        if( AsciiStrCmp(name, path->name) == 0 ) {
            ret = SBCOK;
            if( sw_node_off != NULL ) {
                CopyMem(sw_node_off, &path->sw_node_off, sizeof *sw_node_off);
                //dprint("copy node off  : %lx", sw_node_off);
            }

            if( ver != NULL ) {
                //CopyMem(ver, &path->ver, 256);
                retval = SBC_BlkReadArbitrary((EFI_BLOCK_IO_PROTOCOL *)handle, 
                                              path->sw_node_off,
                                              &node,
                                              sizeof(sw_node_t));
                if(EFI_ERROR(retval)) {
                    eprint("Failed to protected sw reading from 0x%lx offset", path->sw_node_off);
                    ret = SBCIO;
                    goto errdone;
                }

                if(node.pos == 1 && node.sw1 == 1) {
                    CopyMem(ver, &path->ver2, SW_PATH_STR_LEN);
                }
                else {
                    CopyMem(ver, &path->ver, SW_PATH_STR_LEN);
                }

            }

            break;
        }

        path++;
    }

errdone:

    return ret;


}

SBCStatus SBC_UpdateProtecteSWSlotInfo(VOID *handle, CHAR8 *sw_name)
{
    sw_node_t node;
    UINTN node_off;
    [[gnu::unused]]UINTN offset;
    SBCStatus ret = SBCOK;
    boot_proc_t *p = (boot_proc_t *)handle;

    ret = SBC_FindProtectedSw(handle, sw_name, NULL, &node_off);
    SBC_RET_VALIDATE_ERRCODEMSG(!(ret != SBCOK), ret, "Find Protected SW fail");

    ret = SBC_RawAlignedReadBlockIO(p->blkhnd, node_off, sizeof(sw_node_t), &node);
    SBC_RET_VALIDATE_ERRCODEMSG(!(ret != SBCOK), ret, "Update Protected SW Slot Info read fail");

    node.pos ^= 1;

    ret = SBC_RawAlignedWriteBlockIO(p->blkhnd, node_off, sizeof(sw_node_t), &node);
    SBC_RET_VALIDATE_ERRCODEMSG(!(ret != SBCOK), ret, "Update Protected SW Slot Info Write fail");


errdone:
    return ret;

}

SBCStatus SBC_UpdateProtectedSWListVersion(VOID *handle, CHAR8 *sw_name, CHAR8 *sw_ver)
{
    SBCStatus ret = SBCOK;

    UINTN readn;
    UINT8 data[SBC_AT_RP_SYS_CONF_MAX_LEN];
    UINT8 dec_key[SBC_AT_RP_KEY_LEN];

    sw_path_t *path = (sw_path_t *) data;
    UINTN len = sizeof(sw_path_t);
    UINTN cnt, line;

    sw_node_t node;
    EFI_STATUS retval = EFI_SUCCESS;

    ret = SBC_DeviceSecuirtyKeyCreate(dec_key);
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

    ret = SBC_ProtSwLoadRawPrt(handle, dec_key, data, &readn, SYS_CONF_START_OFS + SYS_CONF_SW_LIST_OFS);
    SBC_RET_VALIDATE_ERRCODEMSG(!(ret != SBCOK), ret, "System Configuration Partition Read fail");

    line = readn / len;

    for(cnt = 0; cnt < line; cnt++) {
        dprint("sw_name : %a, path->name :%a  slot1_ver=%a, node : %lx" , 
               sw_name,
               path->ver,
               path->name, 
               path->sw_node_off);

        if( AsciiStrCmp(sw_name, path->name) == 0 ) {
            ret = SBCOK;
;
            retval = SBC_BlkReadArbitrary((EFI_BLOCK_IO_PROTOCOL *)handle, 
                                          path->sw_node_off,
                                          &node,
                                          sizeof(sw_node_t));
            if(EFI_ERROR(retval)) {
                eprint("Failed to protected sw reading from 0x%lx offset", path->sw_node_off);
                ret = SBCIO;
                goto errdone;
            }

            if(node.pos == 1 && node.sw1 == 1) {
                CopyMem(&path->ver2, sw_ver, SW_PATH_STR_LEN);
            }
            else {
                CopyMem(&path->ver, sw_ver, SW_PATH_STR_LEN);
            }

            break;
        }

        path++;
    }




errdone:
    return ret;
}

SBCStatus SBC_ReadProtectedSwSlotOffset(VOID *handle, UINTN *check, CHAR8 *sw_name, UINTN slot, UINTN *offset)
{
    SBCStatus ret = SBCOK;

    sw_node_t node;
    UINTN node_off;
    //UINTN check = 0;

    ret = SBC_FindProtectedSw(handle, sw_name, NULL, &node_off);
    SBC_RET_VALIDATE_ERRCODEMSG(!(ret != SBCOK), ret, "Failed to Find protected SW");

    //dprint("%s s/w node addr 0x%lu", sw_name, node_off);

    ret = SBC_RawAlignedReadBlockIO(((boot_proc_t *)handle)->blkhnd,
                                    node_off,
                                    sizeof(sw_node_t),
                                    &node);
    SBC_RET_VALIDATE_ERRCODEMSG(!(ret != SBCOK), ret, "Failed to SW Node read");

    dprint("[%a sw_node_t]\n", sw_name);
    dprint("status=%c\n", node.status);
    dprint("pos=%u\n", node.pos);
    dprint("sw0=%u\n", node.sw0);
    dprint("sw1=%u\n", node.sw1);
    dprint("sw0_off=%lx\n", node.sw0_off);
    dprint("sw1_off=%lx\n", node.sw1_off);

    if (slot == AT_RP_SW_NODE_SLOT0 && node.sw0 == 1) {
        *check = 1;
        *offset = node.sw0_off;
        goto errdone;
    } 
    else if(slot == AT_RP_SW_NODE_SLOT1 && node.sw1 == 1) {
        *check = 1;
        *offset = node.sw1_off;
        goto errdone;
    }

    //ret = SBCFAIL;

errdone:

    return ret;
}

SBCStatus SBC_RedaPrteoctedSwSize(VOID *handle,  UINTN ofs, UINTN *size)
{
    SBCStatus ret = SBCOK;
    //UINTN length = 0UL;
    boot_proc_t  *p = (boot_proc_t *)handle;

    SBC_RET_VALIDATE_ERRCODEMSG((size != NULL), SBCNULLP, "It's handle point to NULL");

    ret = SBC_RawAlignedReadBlockIO( p->blkhnd, 
                                     ofs,
                                     SBC_RAW_PRTHDR_LEN_OFS,
                                     size);

    SBC_RET_VALIDATE_ERRCODEMSG(!(ret != SBCOK), ret, "Failed to read the Block I/O");


errdone:
    return ret;
}


SBCStatus SBC_RecryptoProtectedSW(VOID *handle, UINTN ofs,  UINT8* sw_secret_key, UINT8 *sw_mig_key)
{
    SBCStatus ret = SBCOK;
    UINTN length = 0ULL;
    boot_proc_t *p = (boot_proc_t *)handle;
    UINTN mvofs = 0;
    UINT8 *dec_mem = NULL;
    UINT8 *enc_mem = NULL;

    aes_buf_t aesbuf; 
    SBC_AESGcmCtx   decctx;
    SBC_AESGcmCtx   encctx;
    SBC_AESContext  aesctx;
    UINT8 *buf = NULL;
    //UINT8 *buf = NULL;

    SBC_RET_VALIDATE_ERRCODEMSG((handle != NULL), SBCNULLP, "Handle Object NULL");
    SBC_RET_VALIDATE_ERRCODEMSG((sw_secret_key != NULL), SBCNULLP, "Handle Object NULL");
    SBC_RET_VALIDATE_ERRCODEMSG((sw_mig_key != NULL), SBCNULLP, "Handle Object NULL");


    dprint("Prot. SW off : %lx", ofs);

    ret = SBC_RedaPrteoctedSwSize(handle, ofs, &length);
    SBC_RET_VALIDATE_ERRCODEMSG(!(ret != SBCOK), ret, "Failed to read the Protected SW Size");
    SBC_RET_VALIDATE_ERRCODEMSG((length != 0), SBCZEROL, "Can't found the Protecde SW");

    dprint("re-crypto sw length : %lu (0x%lx) ", length, length);

    buf = AllocateZeroPool(length + SBC_AT_RP_IV_LEN + SBC_AT_RP_TAG_LEN);
    SBC_RET_VALIDATE_ERRCODEMSG((buf != NULL), SBCNULLP, "Out of Resource");                                                                                                                    

    ret = SBC_RawAlignedReadBlockIO(p->blkhnd,
                                    ofs + SBC_RAW_PRTHDR_LEN_OFS,
                                    length + SBC_AT_RP_IV_LEN + SBC_AT_RP_TAG_LEN,
                                    buf);
    SBC_RET_VALIDATE_ERRCODEMSG(!(ret != SBCOK), ret, "Failed to read the Protected SW");

//  {
//      UINTN node_off;
//      sw_node_t node;
//      //UINTN check = 0;
//
//      ret = SBC_FindProtectedSw(p, gstr_sw_name, NULL, &node_off);
//
//      dprint("============= Before decrypt Node Info =============");
//      dprint(" Node Off : 0x%lu", node_off);
//      ret = SBC_RawAlignedReadBlockIO(p->blkhnd,
//                                  node_off,
//                                  sizeof(sw_node_t),
//                                  &node);
//
//      dprint("[%a sw_node_t]\n", gstr_sw_name);
//      dprint("status=%c\n", node.status);
//      dprint("pos=%u\n", node.pos);
//      dprint("sw0=%u\n", node.sw0);
//      dprint("sw1=%u\n", node.sw1);
//      dprint("sw0_off=%lx\n", node.sw0_off);
//      dprint("sw1_off=%lx\n", node.sw1_off);
//
//      dprint("=========================================");
//  }

    aesbuf.buf = &buf[mvofs];
    mvofs += length;

    //SBC_mem_print_bin("aes encrypt buf", (UINT8 *)aesbuf.buf, 512);
    aesbuf.iv = &buf[mvofs];
    mvofs += SBC_AT_RP_IV_LEN;

    aesbuf.tag = &buf[mvofs];
    mvofs += SBC_AT_RP_TAG_LEN;

    dprint("length of sw=%u", length);
   
    SBC_mem_print_bin("iv=", (UINT8 *)aesbuf.iv, SBC_AT_RP_IV_LEN);
    SBC_mem_print_bin("tag=", (UINT8 *)aesbuf.tag, SBC_AT_RP_TAG_LEN);


    dprint("Key info ");
    SBC_mem_print_bin("Migration Key", sw_mig_key, SBC_AT_HASH_LEN);
    SBC_mem_print_bin("Security Key", sw_secret_key, SBC_AT_HASH_LEN);

    {
        UINT8 hash_check[SBC_AT_HASH_LEN] = {0, };
        SBC_HashCompute(NULL, (UINT8 *)aesbuf.buf, length, hash_check);

        SBC_mem_print_bin("Protected SW Hash", hash_check, 32);
    }

    //
    // Allocate the Encrypt and Decrypt memory 
    //
    dec_mem = AllocateZeroPool(length);
    SBC_RET_VALIDATE_ERRCODEMSG((buf != NULL), SBCNULLP, "Dec buf Out of Resource");

    enc_mem = AllocateZeroPool(length);
    SBC_RET_VALIDATE_ERRCODEMSG((buf != NULL), SBCNULLP, "Enc buf Out of Resource");


    //
    // TODO : Decrypt 
    //
    decctx.msg.value = (void *)aesbuf.buf;
    decctx.msg.length = length;
    decctx.out.value = (void *)dec_mem;
    decctx.out.length = decctx.msg.length;

    aesctx.gcm = &decctx;
    aesctx.algoid = SBC_CIPHER_AES_GCM;

    //SBC_AESGcmSetContext(aesctx.gcm, sw_mig_key, aesbuf.iv, aesbuf.tag);

//  UINT8 auth_tag[] = {
//      0x14 ,0xce ,0x80 ,0x16 ,0x00 ,0x9e ,0x3a ,0x35 ,0xeb ,0x58,
//      0x05 ,0x5d ,0x3c ,0x7d ,0x56 ,0x0d
//  };
//  SBC_AESGcmSetContext(aesctx.gcm, sw_secret_key, aesbuf.iv, auth_tag);
    SBC_AESGcmSetContext(aesctx.gcm, sw_mig_key, aesbuf.iv, aesbuf.tag);

//  SBC_external_mem_print_bin("SBC_RecryptoProtectedSW Dec Key",
//                           (UINT8 *)aesctx.gcm->key.value,
//                           aesctx.gcm->key.length);

#ifdef _TEST_ERROR_SET_    
    if (NvramErr_IsTrue(ERR_PROTSW_DEC)) {
        SBC_BuildHexFormattedMessage(
                (CONST VOID *)sw_mig_key, 32,
                L"SBC_SP_GcmDecrypt Failed the Decrypt (%s)\n",
                mrgmsg, sizeof mrgmsg);

        sbc_err_sysprn(SBC_LOG_CMN_PRIO_ERR, 2,
                 SYS_LOG_HOST_BOOT,
                 SYS_LOG_APP_NAME,
                 SYS_LOG_CSC_NAME,
                 1,
                 SYS_LOG_EVT_DETECTION,
                 mrgmsg);

        ret = SBCFAIL;
        goto errdone;
    }
#endif

    ret = SBC_AESGcmDecrypt(&aesctx);
    SBC_RET_VALIDATE_ERRCODEMSG(!(ret != SBCOK), ret,   "Failed to decrypt"
                                "the Prot SW using MigKey");



//  SBC_external_mem_print_bin("Protected SW Dec Buf",
//                             (UINT8 *)decctx.out.value,
//                             SBC_AT_HASH_LEN);

    //
    // TODO : Re-encrypt
    //

    ZeroMem((void *)&aesctx, sizeof aesctx);
    encctx.msg.value = (void *)dec_mem;
    encctx.msg.length = length;
    encctx.out.value = (void *)enc_mem;
    encctx.out.length = encctx.msg.length;

    aesctx.gcm = &encctx;
    aesctx.algoid = SBC_CIPHER_AES_GCM;

    SBC_AESGcmSetContext(aesctx.gcm, sw_secret_key, aesbuf.iv, aesbuf.tag);
    ret = SBC_AESGcmEncrypt(&aesctx);

    if(ret != SBCOK) {
        sbc_err_sysprn(SBC_LOG_CMN_PRIO_ERR, 2,
                     SYS_LOG_HOST_BOOT,
                     SYS_LOG_APP_NAME,
                     SYS_LOG_CSC_NAME,
                     4,
                     SYS_LOG_EVT_DETECTION,
                     L"SBC_Integrity_Boot mode is NORMAL mode and Reboot");
        goto errdone;
    }
    else {
        sbc_err_sysprn(SBC_LOG_CMN_PRIO_INFO, 2,
                     SYS_LOG_HOST_BOOT,
                     SYS_LOG_APP_NAME,
                     SYS_LOG_CSC_NAME,
                     4,
                     SYS_LOG_EVT_VALDIATION,
                     L"SBC_Integrity_ Protected SW is encrypted using the migration key");
    }


#ifdef _TEST_ERROR_SET_    
    if (NvramErr_IsTrue(ERR_PROTSW_ENC)) {
        SBC_BuildHexFormattedMessage(
                (CONST VOID *)sw_secret_key, 32,
                L"SBC_SP_GcmEncrypt Failed the Encrypt (%s)\n",
                mrgmsg, sizeof mrgmsg);

        sbc_err_sysprn(SBC_LOG_CMN_PRIO_ERR, 2,
                 SYS_LOG_HOST_BOOT,
                 SYS_LOG_APP_NAME,
                 SYS_LOG_CSC_NAME,
                 1,
                 SYS_LOG_EVT_DETECTION,
                 mrgmsg);

        ret = SBCFAIL;
        goto errdone;
    }
#endif 
    //
    // Re-write the protected SW
    //

    dprint("*** 5.8.6.1 4. Protected SW Encrypt --->");
    SBC_external_mem_print_bin("Protected SW Enc Buf", 
                           (UINT8 *)encctx.out.value,
                           SBC_AT_HASH_LEN);
                           //encctx.out.length);
                           

    // Write the Encrypt Data 
#ifdef _TEST_ERROR_SET_    
    if (NvramErr_IsTrue(ERR_PROTSW_WRITE)) {
        sbc_err_sysprn(SBC_LOG_CMN_PRIO_ERR, 2,
                 SYS_LOG_HOST_BOOT,
                 SYS_LOG_APP_NAME,
                 SYS_LOG_CSC_NAME,
                 1,
                 SYS_LOG_EVT_DETECTION,
                 L"SBC_SP_ProtSW Store Fail \n");
        ret = SBCFAIL;
        goto errdone;
    }
#endif    

//  {
//      UINTN node_off;
//      sw_node_t node;
//      //UINTN check = 0;
//
//      ret = SBC_FindProtectedSw(p, gstr_sw_name, NULL, &node_off);
//
//      dprint("============= Before Write Node Info =============");
//      dprint(" Node Off : 0x%lu", node_off);
//      ret = SBC_RawAlignedReadBlockIO(p->blkhnd,
//                                  node_off,
//                                  sizeof(sw_node_t),
//                                  &node);
//
//      dprint("[%a sw_node_t]\n", gstr_sw_name);
//      dprint("status=%c\n", node.status);
//      dprint("pos=%u\n", node.pos);
//      dprint("sw0=%u\n", node.sw0);
//      dprint("sw1=%u\n", node.sw1);
//      dprint("sw0_off=%lx\n", node.sw0_off);
//      dprint("sw1_off=%lx\n", node.sw1_off);
//
//      dprint("=========================================");
//  }

    dprint("*** After encrypt, IV and Tag Information ***");
    SBC_mem_print_bin("protected sw write iv=", (UINT8 *)aesbuf.iv, SBC_AT_RP_IV_LEN);
    SBC_mem_print_bin("protected sw write tag=", (UINT8 *)aesbuf.tag, SBC_AT_RP_TAG_LEN);

    ret = SBC_RawAlignedWriteBlockIO(p->blkhnd, 
                                     ofs + SBC_RAW_PRTHDR_LEN_OFS,
                                     encctx.out.length,
                                     encctx.out.value);

    SBC_RET_VALIDATE_ERRCODEMSG(!(ret != SBCOK), ret, "Failed to write"
                                "the Prot SW");

    // Write the IV Data
    ret = SBC_RawAlignedWriteBlockIO(p->blkhnd, 
                                     ofs + SBC_RAW_PRTHDR_LEN_OFS + encctx.out.length ,
                                     SBC_AT_RP_IV_LEN,
                                     aesbuf.iv);

    SBC_RET_VALIDATE_ERRCODEMSG(!(ret != SBCOK), ret, "Failed to write"
                                "the Prot SW IV");

    // Write the Tag Data
    ret = SBC_RawAlignedWriteBlockIO(p->blkhnd, 
                                     ofs + SBC_RAW_PRTHDR_LEN_OFS + encctx.out.length + SBC_AT_RP_IV_LEN ,
                                     SBC_AT_RP_TAG_LEN,
                                     aesbuf.tag);

    SBC_RET_VALIDATE_ERRCODEMSG(!(ret != SBCOK), ret, "Failed to write"
                                "the Prot SW TAG");

    {
        EFI_STATUS retx = EFI_SUCCESS;
        UINT8  xbuf[128] = {0, };

        retx = SBC_BlkReadArbitrary(p->blkhnd,
                                          ofs + SBC_RAW_PRTHDR_LEN_OFS ,
                                          xbuf,
                                          32);

        SBC_external_mem_print_bin("Protected SW Raw Partition",
                           (UINT8 *)xbuf,
                           32);

        retx = SBC_BlkReadArbitrary(p->blkhnd,
                                          ofs + SBC_RAW_PRTHDR_LEN_OFS + encctx.out.length ,
                                          xbuf,
                                          SBC_AT_RP_IV_LEN);

        dprint("--> Read IV Address  : 0x%lx", ofs + SBC_RAW_PRTHDR_LEN_OFS + encctx.out.length );
        if(!EFI_ERROR(retx)) {

            SBC_mem_print_bin("-->IV", xbuf, SBC_AT_RP_IV_LEN);
        }
        else {
            eprint("Block IO read error(%r)", retx);
        }
        ZeroMem(xbuf, 128);

        retx = SBC_BlkReadArbitrary(p->blkhnd,
                                          ofs + SBC_RAW_PRTHDR_LEN_OFS + encctx.out.length + SBC_AT_RP_IV_LEN ,
                                          xbuf,
                                          SBC_AT_RP_TAG_LEN);

        dprint("--> Read TAG Address  : 0x%lx", ofs + SBC_RAW_PRTHDR_LEN_OFS + encctx.out.length + SBC_AT_RP_IV_LEN );
        if(!EFI_ERROR(retx)) {
  
            SBC_mem_print_bin("-->IV", xbuf, SBC_AT_RP_TAG_LEN);
        }
        else {
            eprint("Block IO read error(%r)", retx);
        }

    }

    sbc_err_sysprn(SBC_LOG_CMN_PRIO_INFO, 2,
             SYS_LOG_HOST_BOOT,
             SYS_LOG_APP_NAME,
             SYS_LOG_CSC_NAME,
             4,
             SYS_LOG_EVT_VALDIATION,
             L"SBC_Integrity_ Protected SW is Saving encrypted block to raw partition");

//  {
//      UINTN node_off;
//      sw_node_t node;
//      //UINTN check = 0;
//
//      ret = SBC_FindProtectedSw(p, gstr_sw_name, NULL, &node_off);
//
//      dprint("============= New Node Info =============");
//      dprint(" Node Off : 0x%lu", node_off);
//      ret = SBC_RawAlignedReadBlockIO(p->blkhnd,
//                                  node_off,
//                                  sizeof(sw_node_t),
//                                  &node);
//
//      dprint("[%a sw_node_t]\n", gstr_sw_name);
//      dprint("status=%c\n", node.status);
//      dprint("pos=%u\n", node.pos);
//      dprint("sw0=%u\n", node.sw0);
//      dprint("sw1=%u\n", node.sw1);
//      dprint("sw0_off=%lx\n", node.sw0_off);
//      dprint("sw1_off=%lx\n", node.sw1_off);
//
//      dprint("=========================================");
//  }

errdone:

    if( buf != NULL ) {
        FreePool(buf);
        buf = NULL;
    }

    if( dec_mem != NULL ) {
        FreePool(dec_mem);
        dec_mem = NULL;
    }

    if( enc_mem != NULL ) {
        FreePool(enc_mem);
        enc_mem = NULL;
    }
    return ret;

}

SBCStatus SBC_ProtSWReCrypto(VOID *handle, UINT8 *key, UINT8 *migkey, UINT8 *decbuf ,UINT32 *declen)
{
    SBCStatus ret = SBCOK;
    boot_proc_t *p = (boot_proc_t *)handle;
    UINTN sw_list_line = 0ULL;
    UINTN x = 0;
    UINTN check = 0;
    UINTN sw_off;

    SBC_RET_VALIDATE_ERRCODEMSG((p != NULL), SBCNULLP, "Invalid Handle Object");

    ret = SBC_ProtSWGetCnt((VOID *)p, &sw_list_line);
    SBC_RET_VALIDATE_ERRCODEMSG((ret == SBCOK), ret, "Protected SW Count read fail");

    for( x = 0; x < sw_list_line; x++) {
        ret = SBC_GetProtectedSwName(handle, x, gstr_sw_name,  sizeof(gstr_sw_name));
        SBC_RET_VALIDATE_ERRCODEMSG(!(ret != SBCOK), ret, "Protected SW Name obtain fail");

        // Software Slot 0
        dprint("Read Protected Sw Slot 0 Offset ");
        ret = SBC_ReadProtectedSwSlotOffset(handle,
                                            &check,
                                            gstr_sw_name,
                                            AT_RP_SW_NODE_SLOT0,
                                            &sw_off);
        if( ret == SBCOK  && check) {
            ret = SBC_RecryptoProtectedSW(handle,
                                          sw_off,
                                          key,
                                          migkey);

            SBC_RET_VALIDATE_ERRCODEMSG(!(ret != SBCOK), ret, "Failed to Re-crypto for Software Slot 1");
        }

        sw_off = 0ULL;
        check = 0ULL;

        // Software Slot 1
        dprint("Read Protected Sw Slot 1 Offset ");
        ret = SBC_ReadProtectedSwSlotOffset(handle,
                                            &check,
                                            gstr_sw_name,
                                            AT_RP_SW_NODE_SLOT1,
                                            &sw_off);
        if( ret == SBCOK  && check ) {
            ret = SBC_RecryptoProtectedSW(handle,
                                          sw_off,
                                          key,
                                          migkey);

            SBC_RET_VALIDATE_ERRCODEMSG(!(ret != SBCOK), ret, "Failed to Re-crypto for Software Slot 2");
        }
    }

errdone:

    return ret;

}

