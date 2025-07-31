#include <Uefi.h>
#include <Library/UefiRuntimeServicesTableLib.h>
#include <Library/BaseLib.h>
#include <Library/ResetSystemLib.h>

#include "SBC_SystemControl.h"
#include "SBC_ErrorType.h"
#include "SBC_BootProc.h"
#include "SBC_FileCtrl.h"


static SBCStatus _sbc_abnormal_processing(VOID *priv)
{
    SBCStatus ret = SBCOK;



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
