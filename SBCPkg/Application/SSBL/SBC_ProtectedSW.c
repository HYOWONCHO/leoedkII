
#include "SBC_FileCtrl.h"


SBCStatus SBC_ProtSWGetCnt(VOID *handle, UINTN *cnt)
{
    SBCStatus ret = SBCOK;
    UINTN sw_list_len;
    UINTN line;
    UINTN sw_list_size = sizeof(sw_path_t);
    UINTN readn; 
    boot_proc_t *p = (boot_proc_t *)handle;

    ret  = SBC_RawAlignedReadBlockIO(p->blkhnd, 
                                     SYS_CONF_START_OFS + SYS_CONF_SW_LIST_OFS,
                                     4,
                                     cnt);
    SBC_RET_VALIDATE_ERRCODEMSG((ret == SBCOK), ret, "Protected SW List Cnt read fail");

    dprint("Protected List Cnt %d", *cnt);

    *cnt = *cnt / sizeof sw_path_t;

    dprint("Protected SW count = %d", *cnt);

errdone:

    return ret;
}


SBCStatus SBC_ProtSWDecrypt(VOID *handle, UINT8 *key, UINT8 *decbuf ,UINT32 *declen)
{

}

