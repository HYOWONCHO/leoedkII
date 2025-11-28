#include <Uefi.h>
#include <Library/UefiRuntimeServicesTableLib.h>
#include <Library/BaseLib.h>
#include <Library/ResetSystemLib.h>
#include <Library/BaseMemoryLib.h>
#include <Library/MemoryAllocationLib.h>
#include <Library/UefiBootServicesTableLib.h>

#include <Library/DevicePathLib.h>
#include <Library/PrintLib.h>
#include <Protocol/SimpleFileSystem.h>
#include <Protocol/BlockIo.h>
//#include <Library/DevicePathToTextLib.h>

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
 * @brief Print FSx: and BLKy: mapping table (UEFI Shell "map" equivalent).
 */
VOID PrintMappingTable()
{
    EFI_STATUS Status;
    EFI_HANDLE *HandleBuffer = NULL;
    UINTN HandleCount = 0;
    UINTN i;

    EFI_SIMPLE_FILE_SYSTEM_PROTOCOL *Sfsp;
    [[maybe_unused]]EFI_BLOCK_IO_PROTOCOL *Blk;
    UINT32 FsIndex = 0;
    [[maybe_unused]]UINT32 BlkIndex = 0;
    //
    // 1. Find all handles
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
        return;
    }



    Print(L"=== Mapping Table ===\n\n");

    //
    // 2. FSx: 출력
    //
    for (i = 0; i < HandleCount; i++) {

        Status = gBS->HandleProtocol(
            HandleBuffer[i],
            &gEfiSimpleFileSystemProtocolGuid,
            (VOID**)&Sfsp
        );

        if (!EFI_ERROR(Status)) {
            EFI_DEVICE_PATH_PROTOCOL *Dp;
            Status = gBS->HandleProtocol(
                HandleBuffer[i],
                &gEfiDevicePathProtocolGuid,
                (VOID**)&Dp
            );
            if (EFI_ERROR(Status)) {
                Print(L"Failed to Found Handle Prototol (%r) \n", Status);
                continue;
            }

            CHAR16 *DpText = ConvertDevicePathToText(Dp, TRUE, FALSE);

            Print(
                L"FS%u: Alias(s):HD%ua:;BLK%u:\n",
                FsIndex,
                FsIndex,
                FsIndex
            );
            Print(L"      %s\n\n", DpText);

            FreePool(DpText);
            FsIndex++;
        }
    }


    //
    // 3. BLKx: 출력
    //
#if 0
    for (i = 0; i < HandleCount; i++) {

        Status = gBS->HandleProtocol(
            HandleBuffer[i],
            &gEfiBlockIoProtocolGuid,
            (VOID**)&Blk
        );

        if (!EFI_ERROR(Status)) {

            EFI_DEVICE_PATH_PROTOCOL *Dp;

            Status = gBS->HandleProtocol(
                HandleBuffer[i],
                &gEfiDevicePathProtocolGuid,
                (VOID**)&Dp
            );
            if (EFI_ERROR(Status)) continue;

            CHAR16 *DpText = ConvertDevicePathToText(Dp, TRUE, FALSE);

            Print(L"BLK%u: Alias(s):\n", BlkIndex);
            Print(L"      %s\n\n", DpText);

            FreePool(DpText);
            BlkIndex++;
        }
    }
#endif
    gBS->FreePool(HandleBuffer);
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

    gBS->Stall(50000); 
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
    sbc_err_sysprn(SBC_LOG_CMN_PRIO_INFO, 2,
         SYS_LOG_HOST_BOOT,
         SYS_LOG_APP_NAME,
         SYS_LOG_CSC_NAME,
         1,
         L"Detectoin",
         L"SBC_VENDOR_SP System Shutdown - Boot State Ab-normal");
#ifndef _ALL_PASS_
  gRT->ResetSystem(EfiResetShutdown, EFI_SUCCESS, 0, NULL);
#endif
  return;
}
