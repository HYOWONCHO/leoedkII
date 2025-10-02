
#include "SBC_ProtectedSW.h"
#include "SBC_FileCtrl.h"
#include "SBC_BootProc.h"
#include "SBC_AntiTampering.h"

#include "SBC_Config.h"

extern CHAR16 mrgmsg[8192];

#define SBC_PROT_SYS_DATA_LEN           4


SBCStatus SBC_LoadSysFile(VOID *handle, UINTN offset, UINT8 *deckey, UINT8* data)
{

    SBCStatus ret = SBCOK;

    UINT8 iv[SBC_AT_RP_IV_LEN], tag[SBC_AT_RP_TAG_LEN];
    UINT8 enc[SBC_AT_RP_SYS_CONF_MAX_LEN], dec[SBC_AT_RP_SYS_CONF_MAX_LEN];
    UINT32 enc_len;
    boot_proc_t *p = (boot_proc_t *)handle;
    SBC_AESContext aesctx;
    SBC_AESGcmCtx  ctx;

    ret = SBC_RawAlignedReadBlockIO(p->blkhnd,
                                    offset,
                                    &enc_len,
                                    4);
    SBC_RET_VALIDATE_ERRCODEMSG(!(ret != SBCOK), ret, "Block IO read fail");

    ret = SBC_RawAlignedReadBlockIO(p->blkhnd,
                                    offset + SBC_PROT_SYS_DATA_LEN,
                                    enc,
                                    enc_len);
    SBC_RET_VALIDATE_ERRCODEMSG(!(ret != SBCOK), ret, "Block IO read fail");

    ret = SBC_RawAlignedReadBlockIO(p->blkhnd,
                                    offset + SBC_PROT_SYS_DATA_LEN + enc_len,
                                    iv,
                                    SBC_AT_RP_IV_LEN);
    SBC_RET_VALIDATE_ERRCODEMSG(!(ret != SBCOK), ret, "Block IO read fail");

    ret = SBC_RawAlignedReadBlockIO(p->blkhnd,
                                    offset + SBC_PROT_SYS_DATA_LEN + enc_len + SBC_AT_RP_IV_LEN,
                                    tag,
                                    SBC_AT_RP_TAG_LEN);
    SBC_RET_VALIDATE_ERRCODEMSG(!(ret != SBCOK), ret, "Block IO read fail");

    //
    // Decrypt 
    //
    ctx.out.value = (void *)enc;
    ctx.out.length = enc_len;
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
                     L"AT_BOOT",
                     L"SSBL",
                     L"SAT",
                     8,
                     L"Validation",
                     L"SBC_RawFS_Key Creation Fail");
        goto errdone;
    }


    //boot_proc_t *p = (boot_proc_t *)handle; 
    ret = SBC_LoadRawPrt(handle, deckey, decbuf, &rdlen, SYS_CONF_START_OFS + SYS_CONF_SW_LIST_OFS);
    if( ret != SBCOK ) {
        SBC_LogHexToStrChar16(deckey, 32, err_out_key_val, sizeof(err_out_key_val)/sizeof(err_out_key_val[0]),  FALSE, 0);
        UnicodeSPrint(mrgmsg,  sizeof mrgmsg, L"SBC_ProtSW_Update Failed to decrypt (%s) \n", err_out_key_val);
        sbc_err_sysprn(SBC_LOG_CMN_PRIO_ERR, 2,
                 L"AT_BOOT",
                 L"SSBL",
                 L"SAT",
                 5,
                 L"Detection",
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

    CopyMem(sw_name, &path->name, sw_name_size);

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


    wrbuf = AllocatePool(wrbuf_len);
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
    size_t  readn;
    UINT8   data[SBC_AT_RP_SYS_CONF_MAX_LEN] = {0, };
    UINT8   dec_key[SBC_AT_RP_KEY_LEN] = {0, };
    boot_proc_t *p = (boot_proc_t *)handle;

    sw_path_t *path = (sw_path_t *)data;
    UINTN len = sizeof(sw_path_t);
    UINTN cnt, line;

    ret = SBC_DeviceSecuirtyKeyCreate(dec_key);
    if( ret != SBCOK ) {
        sbc_err_sysprn(SBC_LOG_CMN_PRIO_ERR, 1,
                     L"AT_BOOT",
                     L"SSBL",
                     L"SAT",
                     8,
                     L"Validation",
                     L"SBC_RawFS_Key Creation Fail");
        goto errdone;
    }

    ret = SBC_LoadRawPrt(handle, dec_key, data, &readn, SYS_CONF_START_OFS + SYS_CONF_SW_LIST_OFS);
    SBC_RET_VALIDATE_ERRCODEMSG(!(ret != SBCOK), ret, "System Configuration Partition Read fail");

    for(cnt = 0; cnt < line, cnt++) {
        if( AsciiStrCmp(name, path->name) == 0 ) {
            ret = SBCOK;
            if( sw_node_off != NULL ) {
                CopyMem(sw_node_off, &path->sw_node_off, sizeof *sw_node_off);
            }

            if( ver != NULL ) {
                CopyMem(ver, &path->ver, 256);
            }
        }

        path++;
    }

errdone:

    return ret;


}

SBCStatus SBC_UpdateProtecteSWSlotInfo(VOID *handle, CHAR8 *sw_name)
{
    sw_node_t node;
    UINTN node_off, offset;
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

    size_t readn;
    UINT8 data[SBC_AT_RP_SYS_CONF_MAX_LEN];
    UINT8 dec_key[SBC_AT_RP_KEY_LEN];

    sw_path_t *path = (sw_path_t *) data;
    UINTN len = sizeof(sw_path_t);
    UINTN cnt, line;

    ret = SBC_DeviceSecuirtyKeyCreate(dec_key);
    if( ret != SBCOK ) {
        sbc_err_sysprn(SBC_LOG_CMN_PRIO_ERR, 1,
                     L"AT_BOOT",
                     L"SSBL",
                     L"SAT",
                     8,
                     L"Validation",
                     L"SBC_RawFS_Key Creation Fail");
        goto errdone;
    }

    ret = SBC_LoadRawPrt(handle, dec_key, data, &readn, SYS_CONF_START_OFS + SYS_CONF_SW_LIST_OFS);
    SBC_RET_VALIDATE_ERRCODEMSG(!(ret != SBCOK), ret, "System Configuration Partition Read fail");

    line = readn / len;

    for(cnt= 0; cnt < line; cnt++) {
        dprint("name=%a, ver=%a, sw_node_off=%lx\n",path->name, path->ver, path->sw_node_off);
        if( AsciiStrCmp(sw_name, path->name) == 0 ) {
            CopyMem(path->ver, sw_ver, 256);
            ret = SBCOK;
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

    if (slot == AT_RP_SW_NODE_SLOT0 || node.sw0 == 1) {
        *check = 1;
        *offset = node.sw0_off;
    } 
    else if(slot == AT_RP_SW_NODE_SLOT1 && node.sw1 == 1) {
        *check = 1;
        *offset = node.sw1_off;
    }

errdone:

    return ret;
}


SBCStatus SB_RecryptoProtectedSW(VOID *handle, UINT8* sw_secret_key, UINT8 *sw_mig_key)
{
    SBCStatus ret = SBCOK;



errdone:

    return ret;

}

SBCStatus SBC_ProtSWDecrypt(VOID *handle, UINT8 *key, UINT8 *decbuf ,UINT32 *declen)
{
    SBCStatus ret = SBCOK;
    boot_proc_t *p = (boot_proc_t *)handle;
    UINTN sw_list_line = 0ULL;
    UINTN x = 0;
    UINTN check = 0;
    UINTN sw_off;


    CHAR8 sw_name[SBC_AT_RP_SW_NAME_MAX] = {0, };


    SBC_RET_VALIDATE_ERRCODEMSG((p != NULL), SBCNULLP, "Invalid Handle Object");

    ret = SBC_ProtSWGetCnt((VOID *)p, &sw_list_line);
    SBC_RET_VALIDATE_ERRCODEMSG((ret == SBCOK), ret, "Protected SW Count read fail");

    for( x = 0; x < sw_list_line; x++) {
        ret = SBC_GetProtectedSwName(handle, x, sw_name,  sizeof(sw_name));
        SBC_RET_VALIDATE_ERRCODEMSG(!(ret != SBCOK), ret, "Protected SW Name obtain fail");
        ret = SBC_ReadProtectedSwSlotOffset(handle,
                                          sw_name,
                                          &check,
                                          AT_RP_SW_NODE_SLOT0,
                                          &sw_off);
        if( check == 1 ) {
            ret = SBC_RecryptoProtectedSW(sw_off, key, 
        }

                                                    

        

    }




errdone:

    return ret;

}

