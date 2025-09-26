
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


SBCStatus SBC_ProtSWDecrypt(VOID *handle, UINT8 *key, UINT8 *decbuf ,UINT32 *declen)
{
    SBCStatus ret = SBCOK;
    boot_proc_t *p = (boot_proc_t *)handle;
    UINTN sw_list_line = 0ULL;
    UINTN x = 0;

    CHAR8 sw_name[SBC_AT_RP_SW_NAME_MAX] = {0, };


    SBC_RET_VALIDATE_ERRCODEMSG((p != NULL), SBCNULLP, "Invalid Handle Object");

    ret = SBC_ProtSWGetCnt((VOID *)p, &sw_list_line);
    SBC_RET_VALIDATE_ERRCODEMSG((ret == SBCOK), ret, "Protected SW Count read fail");

    for( x = 0; x < sw_list_line; x++) {
        ret = SBC_GetProtectedSwName(handle, x, sw_name,  sizeof(sw_name));
        SBC_RET_VALIDATE_ERRCODEMSG(!(ret != SBCOK), ret, "Protected SW Name obtain fail");


    }




errdone:

    return ret;

}

