#include <Uefi.h>
#include <Library/UefiRuntimeServicesTableLib.h>
#include <Library/BaseLib.h>
#include <Library/ResetSystemLib.h>
#include <Library/BaseMemoryLib.h>
#include <Library/MemoryAllocationLib.h>
#include <Library/UefiBootServicesTableLib.h>

#include "SBC_SystemControl.h"
#include "SBC_AntiTampering.h"
#include "SBC_Hashing.h"
#include "SBC_CryptAES.h"
#include "SBC_EccSignVerify.h"

//#include "SBC_BootProc.h"
#include "SBC_FileCtrl.h"
#include "SBC_Kdf.h"
#include "SBC_UnitTest.h"


SBCStatus SBC_BootKeyModeChange(UINT32 newbm, UINT32 newkey, VOID *priv)
{
    SBCStatus ret = SBCOK;
    boot_proc_t *bp = (boot_proc_t *)priv;
    rawprt_hdr_t *hdr = NULL;
    UINT8 wrbuf[512] = {0,};

    hdr = (rawprt_hdr_t *)bp->rawprt_hdr;

    hdr->bootmode = newbm;
    hdr->keymode = newkey;
    hdr->rcvmode = 0;

    if(bp->bm == BOOT_MODE_RECOVERY) {
        hdr->rcvmode = SBC_BOOT_DISCOVER_FROM_REOCVERY;
    }

    //SBC_external_mem_print_bin("Boot Mode Change", (UINT8 *)hdr, 128);

    //dprint();
    SBC_RET_VALIDATE_ERRCODEMSG((bp->blkhnd != NULL), SBCNULLP, "Raw Partition Block IO Handle Nill");

    //dprint();
    CopyMem(wrbuf, (void *)hdr, sizeof *hdr);
    SBC_external_mem_print_bin("Mode Change", wrbuf, 128);
    // Boot Mode write
    ret = SBC_RawPrtBlockWrite(bp->blkhnd,(UINT8 *)wrbuf, 512,0);
    SBC_RET_VALIDATE_ERRCODEMSG((ret == SBCOK), ret, "Boot and Key mode write fail");


errdone:

    return ret;
}

/**
 * @brief Reconnect all drivers to all controllers (equivalent to Shell "map -r").
 *
 * @return EFI_STATUS
 */
EFI_STATUS MapRebuild(VOID)
{
    EFI_STATUS Status;
    EFI_HANDLE *HandleBuffer = NULL;
    UINTN HandleCount = 0;
    UINTN i;

    //
    // Step 1: Get all handles
    //
    Status = gBS->LocateHandleBuffer(
        AllHandles,
        NULL,
        NULL,
        &HandleCount,
        &HandleBuffer
    );

    if (EFI_ERROR(Status)) {
        Print(L"LocateHandleBuffer failed: %r\n", Status);
        return Status;
    }

    Print(L"Found %u handles. Reconnecting...\n", HandleCount);

    //
    // Step 2: Reconnect every handle's controller
    //
    for (i = 0; i < HandleCount; i++) {

        gBS->DisconnectController(
            HandleBuffer[i],
            NULL,
            NULL
        );

        gBS->ConnectController(
            HandleBuffer[i],
            NULL,
            NULL,
            TRUE
        );
    }

    Print(L"Reconnect complete.\n");

    gBS->FreePool(HandleBuffer);
    return EFI_SUCCESS;
}


VOID SBC_RebootSystem(VOID)
{
  Print(L"Reset SBC System ... \n");
#ifndef _ALL_PASS_
  gRT->ResetSystem(EfiResetCold, EFI_SUCCESS, 0, NULL);
#endif
  return;
}


VOID SBC_ShutdownSystem(VOID)
{
  Print(L"Shutting down SBC System ... \n");
#ifndef _ALL_PASS_
  gRT->ResetSystem(EfiResetShutdown, EFI_SUCCESS, 0, NULL);
#endif
  return;
}
