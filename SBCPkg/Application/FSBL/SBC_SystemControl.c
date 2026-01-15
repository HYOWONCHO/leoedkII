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

#include "SBC_Log.h"
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
  Print(L"\033[33mReset SBC System ...\033[0m\n");
#ifndef _ALL_PASS_
#ifdef _LOG_RECODING_
    SBC_LogDeinit(&gLogCtx);
#endif
  gRT->ResetSystem(EfiResetCold, EFI_SUCCESS, 0, NULL);
  //ASSERT(FALSE);
  while(TRUE) { };
#endif
  return;
}


VOID SBC_ShutdownSystem(VOID)
{
    Print(L"\033[33mShutdown SBC System ...\033[0m\n");
    sbc_err_sysprn(SBC_LOG_CMN_PRIO_INFO, 2,
         SYS_LOG_HOST_BOOT,
         SYS_LOG_APP_NAME,
         SYS_LOG_CSC_NAME,
         1,
         L"Detectoin",
         L"SBC_VENDOR_SP System Shutdown - Boot State Ab-normal");
#ifndef _ALL_PASS_
#ifdef _LOG_RECODING_
    SBC_LogDeinit(&gLogCtx);
#endif
  gRT->ResetSystem(EfiResetShutdown, EFI_SUCCESS, 0, NULL);
  while(TRUE) { };
#endif
  return;
}

void SBC_UpdateBootPres(
    UINT8 *pres_buf, 
    UINT32 cur, 
    INT32 prev)
{
    if (!pres_buf)
        return;

    /* cur / prev has ans non value  */
    if (cur == 0 || prev == 0)
        return;

    /*
     * pres_buf structure:
     * [0] value slot     ← determined by pres_buf[1]
     * [1] tag ('C' or 'P')
     *
     * [2] value slot     ← determined by pres_buf[3]
     * [3] tag ('C' or 'P')
     */
    for (UINT32 i = 0; i < 2; i++) {
        UINT32 v = i * 2;
        UINT32 t = v + 1;
        CHAR8 tag = pres_buf[t];

        if (tag == 'C') {
            pres_buf[v] = cur;
        } else if (tag == 'P') {
            pres_buf[v] = prev;
        }
    }
}

SBCStatus SBC_RawPrtHdrChange(
    VOID *handle,
    UINT32 cur, UINT32 prev, 
    UINT32 prevmode, 
    UINT32 bm, 
    UINT32 km)
{
    SBCStatus ret = SBCOK;
    [[maybe_unused]]EFI_STATUS retval = EFI_SUCCESS;
    boot_proc_t *b_proc = (boot_proc_t *)handle;
    rawprt_hdr_t rawhdr;
    UINT8 *pres_buf;


    ZeroMem(&rawhdr, sizeof(rawhdr));;

    ret = SBC_RawAlignedReadBlockIO(b_proc->blkhnd,
                                    0x0,
                                    sizeof rawhdr,
                                    (void *)&rawhdr);
    if (ret != SBCOK) {
        eprint("SBC_RawAlignedReadBlockIO 0x%lu read fail", 0x0);
        goto errdone;
    }

    dprint("Boot Header Read ===>");
    SBC_mem_print_bin("Raw Partition Header ", (UINT8 *)&rawhdr, sizeof rawhdr);

    rawhdr.prevmode = prevmode;
    pres_buf = rawhdr.bootpres;
    dprint("%d:%02x %d:%c %d:%02x %d:%c \n",
            0, pres_buf[0], 
            1, pres_buf[1], 
            2, pres_buf[2], 
            3, pres_buf[3]);


    /* pres_buf mapping:
     * [0] - current or previous value slot
     * [1] - prev for slot 0 ('C' or 'P')
     * [2] - current or previous value slot
     * [3] - prev for slot 2 ('C' or 'P')
     */

//  if (cur != 0 && prev != 0) {
//      if (pres_buf[1] == 'C' || pres_buf[1] == 'P') {
//          pres_buf[0] = (pres_buf[1] == 'C') ? cur : prev;
//      }
//
//      if (pres_buf[3] == 'C' || pres_buf[3] == 'P') {
//          pres_buf[2] = (pres_buf[3] == 'C') ? cur : prev;
//      }
//  }


    SBC_UpdateBootPres(pres_buf, cur, prev);

    SBC_mem_print_bin("Raw Partition Boot Pres ", (UINT8 *)rawhdr.bootpres, sizeof rawhdr.bootpres);

    if (bm != BOOT_MODE_UNKNOWN) {
        rawhdr.bootmode = bm;
        // Comment by Leon - Do not need 
//      if(bm == BOOT_MODE_RECOVERY) {
//          dprint("---> Next Firmware Start, SHOULD be power-on from Recovery Mode");
//          rawhdr.rcvmode = 1;
//      }
    }
    
    if (km != KEY_MODE_UNKNOWN) {
        rawhdr.keymode = km;
    }

    ret = SBC_RawAlignedWriteBlockIO(b_proc->blkhnd,
                                    0x0,
                                    sizeof rawhdr,
                                    (void *)&rawhdr);
    if (ret != SBCOK) {
        eprint("SBC_RawAlignedWriteBlockIO 0x%lu read fail", 0x0);
        goto errdone;
    }


    ret = SBC_RawAlignedReadBlockIO(b_proc->blkhnd,
                                    0x0,
                                    sizeof rawhdr,
                                    (void *)&rawhdr);
    if (ret != SBCOK) {
        eprint("After write, SBC_RawAlignedReadBlockIO 0x%lu read fail", 0x0);
        goto errdone;
    }

    dprint("Afer write, Boot Header Read ===>");
    SBC_mem_print_bin("Raw Partition Header ", (UINT8 *)&rawhdr, sizeof rawhdr);
errdone:

    return ret;
}

SBCStatus SBC_SecureBootUpdateScenario(VOID *priv)
{
    SBCStatus   ret      = SBCOK;
    boot_proc_t *p       = (boot_proc_t *)priv;
    UINT32      key_mode = KEY_MODE_UNKNOWN;
    UINT32      next_bm  = BOOT_MODE_UNKNOWN;
    //UINT32      stay_prev_mode = 0;

    if (p == NULL) {
        return SBCNULLP;
    }

    if (p->bootst == SB_PROC_ST_NRMA) {
        return ret;
    }

    if (p->bm  == BOOT_MODE_RECOVERY) {
        dprint("Recovery Mode Boot Abnormal");

        sbc_err_sysprn(SBC_LOG_CMN_PRIO_INFO, 2,
             SYS_LOG_HOST_BOOT,
             SYS_LOG_APP_NAME,
             SYS_LOG_CSC_NAME,
             8,
             SYS_LOG_EVT_VALDIATION,
             L"SBC_tamper_Updated boot firmware invalid and initiating rollback to factory version\n");

        
        ret = SBC_RawPrtHdrChange(
              p,
              0,
              0,
              p->prevmode,
              BOOT_MODE_FACTORY,
              KEY_MODE_UPDATE   /* ← 여기서 이제 실제로 key_mode 사용 */
          );

        sbc_err_sysprn(SBC_LOG_CMN_PRIO_INFO, 2,
             SYS_LOG_HOST_BOOT,
             SYS_LOG_APP_NAME,
             SYS_LOG_CSC_NAME,
             8,
             SYS_LOG_EVT_VALDIATION,
             L"SBC_Integrity_Boot mode is FACTORY mode and Reboot\n");


        SBC_RebootSystem();
    }

    sbc_err_sysprn(SBC_LOG_CMN_PRIO_INFO, 2,
                   SYS_LOG_HOST_BOOT,
                   SYS_LOG_APP_NAME,
                   SYS_LOG_CSC_NAME,
                   1,
                   SYS_LOG_EVT_VALDIATION,
                   L"SBC_VENDOR_FP FSBL Change Boot Mode based on "
                   L"Normal Mode Ab-normal state");

    key_mode = (p->bm == BOOT_MODE_UPDATE) ? KEY_MODE_UPDATE : KEY_MODE_BOOT;
    dprint("KeyMode Selected = %d", key_mode);


    switch (p->prevmode) {
    case 0:
        next_bm = BOOT_MODE_FACTORY;
        break;

    case 1:
        next_bm = BOOT_MODE_RECOVERY;
        break;

    default:
        ret = SBCINVPARAM;
        goto errdone;
    }

    ret = SBC_RawPrtHdrChange(
              p,
              0,
              0,
              p->prevmode,
              next_bm,
              key_mode   /* ← 여기서 이제 실제로 key_mode 사용 */
          );

    if (ret != SBCOK) {
        sbc_err_sysprn(SBC_LOG_CMN_PRIO_ERR, 2,
                       SYS_LOG_HOST_BOOT,
                       SYS_LOG_APP_NAME,
                       SYS_LOG_CSC_NAME,
                       1,
                       SYS_LOG_EVT_VALDIATION,
                       L"SBC_VENDOR_FP FSBL Shutdown from Abnormal of Normal or Update Boot Mode");
        goto errdone;
    }

    sbc_err_sysprn(SBC_LOG_CMN_PRIO_INFO, 2,
                   SYS_LOG_HOST_BOOT,
                   SYS_LOG_APP_NAME,
                   SYS_LOG_CSC_NAME,
                   1,
                   SYS_LOG_EVT_VALDIATION,
                   L"SBC_VENDOR_FP FSBL Reset from Abnormal of Normal or Update Boot Mode");

    SBC_RebootSystem();

errdone:
    return ret;
}


