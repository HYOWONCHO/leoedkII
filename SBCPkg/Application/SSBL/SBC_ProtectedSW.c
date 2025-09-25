
#include "SBC_ProtectedSW.h"
#include "SBC_FileCtrl.h"
#include "SBC_BootProc.h"
#include "SBC_AntiTampering.h"



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

SBCStatus SBC_GetProtectedSwName(UINTN st, CHAR8 *sw_name, UINTN sw_name_size)
{
    SBCStatus ret = SBCOK;

    UINT8 data[SBC_AT_RP_SYS_CONF_MAX_LEN]  = {0,};
    UINT8 dec_key[SBC_AT_RP_KEY_LEN] = {0,};

    ret = SBC_DeviceSecuirtyKeyCreate(dec_key);
    SBC_RET_VALIDATE_ERRCODEMSG((ret == SBCOK), ret, "Protected SW List Cnt read fail");





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

