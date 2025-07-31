#include <Uefi.h>
#include <Library/UefiRuntimeServicesTableLib.h>
#include <Library/BaseLib.h>
#include <Library/ResetSystemLib.h>

#include "SBC_SystemControl.h"
#include "SBC_ErrorType.h"
#include "SBC_BootProc.h"
#include "SBC_FileCtrl.h"

static BOOL _check_prev_fw(UINTN prev_bnk_id)
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

errdone;

    return ret;

}


SBCStatus  SBC_SecureBootCheck(VOID *priv)
{
    SBCStatus ret = SBCOK;

    boot_proc_t *bp = (boot_proc_t *)priv;

    switch(bp->bm) {
    case BOOT_MODE_NORMAL:
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
