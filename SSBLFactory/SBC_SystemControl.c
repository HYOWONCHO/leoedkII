#include <Uefi.h>
#include <Library/UefiRuntimeServicesTableLib.h>
#include <Library/BaseLib.h>
#include <Library/ResetSystemLib.h>

#include "SBC_SystemControl.h"
#include "SBC_ErrorType.h"
#include "SBC_BootProc.h"
#include "SBC_FileCtrl.h"

//EFI_GUID g_sbc_guid  = {0x1F3F7E80, 0xDB6B, 0x93FA, {0x9E, 0x61, 0x4C, 0x31, 0x3D, 0x3A}};

static BOOLEAN _check_prev_fw(UINTN prev_bnk_id)
{
    if(prev_bnk_id == 0) {
        return FALSE;
    }

    // Load the 
}


static SBCStatus _sbc_abnormal_processing(VOID *priv)
{
    SBCStatus ret = SBCOK;

    boot_proc_t *bp = (boot_proc_t *)priv;

    // Check the key mode
    switch(bp->km) {
    case KEY_MODE_NORMAL:
        // Check which existense the previously firmware 
        if(_check_prev_fw(bp->pvs_sw_bnk) != TRUE) {
            // Boot Mode changes from Normmal to Factory
            //(boot_proc_t *)
        }
        break;
    default:
        goto errdone;
    }

errdone:

    return ret;

}


SBCStatus  SBC_SecureBootCheck(VOID *priv)
{
    SBCStatus ret = SBCOK;
    //BOOLEAN   bret = FALSE;

    boot_proc_t *bp = (boot_proc_t *)priv;

    switch(bp->bm) {
    case BOOT_MODE_NORMAL:
        if(bp->bootst == SB_PROC_ST_ABNRAM) {
            if(_sbc_abnormal_processing(priv) != TRUE) {
                // TODO : error processing
            }
        }
        
        break;
    default:
      goto errdone;
      //break;
    }

    


errdone:
    return ret;

}



VOID SBC_RebootSystem(VOID)
{
  //Print(L"Rebooting ... \n");
    gRT->ResetSystem(EfiResetCold, EFI_SUCCESS, 0, NULL);
    return;
}


VOID SBC_ShutdownSystem(VOID)
{
  //Print(L"Shutting down ... \n");
    gRT->ResetSystem(EfiResetShutdown, EFI_SUCCESS, 0, NULL);
    return;
}
