#include <Uefi.h>
#include <Library/UefiRuntimeServicesTableLib.h>
#include <Library/BaseLib.h>
#include <Library/ResetSystemLib.h>

#include "SBC_SystemControl.h"

#include "SBC_BootProc.h"
#include "SBC_FileCtrl.h"

//EFI_GUID g_sbc_guid  = {0x1F3F7E80, 0xDB6B, 0x93FA, {0x9E, 0x61, 0x4C, 0x31, 0x3D, 0x3A}};

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

    hdr = (rawprt_hdr_t *)bp->rawprt_hdr;

    hdr->bootmode = newbm;
    hdr->keymode = newkey;


    SBC_RET_VALIDATE_ERRCODEMSG((bp->blkhnd != NULL), SBCNULLP, "Raw Partition Block IO Handle Nill");

    // Boot Mode write
    ret = SBC_RawPrtBlockWrite(bp->blkhnd,(UINT8 *)hdr, sizeof(*hdr),0);
    SBC_RET_VALIDATE_ERRCODEMSG((ret == SBCOK), ret, "Boot and Key mode write fail");


errdone:

    return ret;
}


static VOID _sbc_abnormal_processing(VOID *priv)
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

VOID SBC_RecoveryBootProcessing(VOID *priv)
{
    SBCStatus ret = SBCOK;
    sb_rcv_proc_t *p = NULL;
    boot_proc_t   *bt_proc = NULL; // BOot process
    UINT8 sk[BASE_ANS_KEY_STR] = {0,}; // Secret key for Protected SW 

    p = (sb_rcv_proc_t *)priv;
    bt_proc = (boot_proc_t *)p->handle;

    if(_check_prev_fw(bt_proc->pvs_sw_bnk) != FALSE) {
        // System Shutdown
        goto errdone;
       
    }

    // Create the OSID

    // Baseanswer Ecnrypt and Store
    ret = SBC_BaseAnswerEncryptStore(
                    bt_proc->blkhnd,
                    ((LV_t *)p->baseans)->value,
                    ((LV_t *)p->baseans)->length,
                    (UINT8 *)p->osid,
                    BASE_ANS_KEY_STR
    );


    SBC_RET_VALIDATE_ERRCODEMSG((ret == SBCOK),ret, "Base Answer re-write faie");

    // Create the secret key
    ret = SBC_HashCompute(NULL, p->osid, BASE_ANS_KEY_STR, sk);
    SBC_RET_VALIDATE_ERRCODEMSG((ret == SBCOK), ret, "Secret key create fail");

    // Load protected SW 

    return;

errdone:
    SBC_ShutdownSystem();
    return;
}


SBCStatus  SBC_SecureBootCheck(VOID *priv)
{
    SBCStatus ret = SBCOK;
    //VOID        *new_hnd = NULL;
    //BOOLEAN   bret = FALSE;

    boot_proc_t *bp = (boot_proc_t *)priv;

    switch(bp->bm) {
    case BOOT_MODE_NORMAL:
        if(bp->bootst == SB_PROC_ST_ABNRAM) {

            // In case of the Boot Mode is Normal and Boot State is Abnormal.
            _sbc_abnormal_processing(priv);
                // TODO : error processing
            SBC_RebootSystem();
        }

        break;
    case BOOT_MODE_RECOVERY:
        
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
    while(TRUE) { };

}


VOID SBC_ShutdownSystem(VOID)
{
  //Print(L"Shutting down ... \n");
    gRT->ResetSystem(EfiResetShutdown, EFI_SUCCESS, 0, NULL);
    while(TRUE) { };
}
