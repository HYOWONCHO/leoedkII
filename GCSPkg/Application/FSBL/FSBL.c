/** @file
  Brief Description of UEFI MyHelloWorld
  Detailed Description of UEFI MyHelloWorld
  Copyright for UEFI MyHelloWorld
  License for UEFI MyHelloWorld
**/


#include <Uefi.h>
#include <Library/PcdLib.h>
#include <Library/UefiLib.h>
#include <Library/UefiApplicationEntryPoint.h>
//#include <Libray/RngLib.h>

#include <Library/BaseLib.h>
//#include <Library/CtLibSuppot.h>
#include <Library/BaseCryptLib.h>
#include <Library/BaseMemoryLib.h>
#include <malloc.h>
#include <Register/Intel/Cpuid.h>

#include <Library/ShellLib.h>
#include <Library/MemoryAllocationLib.h>
#include <Protocol/Smbios.h>

#include <Library/DevicePathLib.h>
#include <string.h>
#include <stdio.h>
#include <stdlib.h>

// Block Io
#include <Protocol/BlockIo.h>
#include <Protocol/DiskInfo.h>
#include <Protocol/SerialIo.h>
// Serial 
#include <Library/SerialPortLib.h>
#include <Library/PcdLib.h>
#include "leo_test.h"
// Length value


#include <Library/UefiBootServicesTableLib.h>
#include <Library/FileHandleLib.h>

#include <Protocol/Smbios.h>

#include <Library/UnitTestLib.h>

#include <Library/UefiBootManagerLib.h>

#include <Library/UefiLib/UefiLibInternal.h>
#include <Library/PcdLib.h>

#include <openssl/objects.h>
#include <openssl/bn.h>
#include <openssl/ec.h>
#include <stdarg.h>

#include "SBC_Log.h"
#include "SBC_ErrorType.h"
#include "SBC_CryptAES.h"
#include "SBC_FileCtrl.h"
#include "SBC_TypeDefs.h"
#include "SBC_EccSignVerify.h"
#include "SBC_Config.h"
#include "SBC_AntiTampering.h"
#include "SBC_Util.h"
#include "SBC_UnitTest.h"
#include "SBC_Nvram.h"
#include "SBC_SystemControl.h"
#include "SBC_Timer.h"
#include "SBC_Kdf.h"

#ifdef _SBC_TPM_
#include "SBC_Tpm.h"
#endif


extern VOID SBC_ShutdownSystem(VOID);
extern SBCStatus SBC_GRUB_LoadAndStart(EFI_HANDLE ImageHandle);

UINTN   sys_start_time = 0ULL;
UINTN   sys_end_time = 0ULL;
UINTN   sys_ns_var = 0ULL;




VOID *h_blkio;               // Block I/O handle

#ifndef _FSBL_TEST_
static rawprt_hdr_t *tmp_prtheader;    // Raw Partition Header handle

#endif
//static BOOLEAN        is_boot_status; 
const unit_proc_t *tmp_btproc;
extern SBCStatus SBC_SSBL_LoadAndStart(EFI_HANDLE ImageHandle);

SBCStatus  SBC_DiceKeysGen(EFI_HANDLE ImageHandle, VOID *p,UINTN normbank, UINTN bm)
{
    SBCStatus ret = SBCOK;
    atp_ident_t *h = NULL;

    (VOID)ImageHandle;


    h = (atp_ident_t *)p;

    ret = SBC_GenDeviceID(h->devid);
    if (ret != SBCOK) {
        //Print(L"Device ID generate fail \n");
        goto errdone;
    }
//
    SBC_mem_print_bin("Device ID", h->devid, sizeof h->devid);
    ret = SBC_GenFWID(ImageHandle, h->devid, h->fwid, normbank, bm);
    if (ret != SBCOK) {
        //Print(L"FW ID generate fail \n");
        goto errdone;
    }

    SBC_mem_print_bin("Firmware ID", h->fwid, sizeof h->fwid);

    ret = SBC_GenOSID(ImageHandle,  h->fwid, h->osid);
    if (ret != SBCOK) {
        //Print(L"FW ID generate fail \n");
        goto errdone;
    }

    SBC_mem_print_bin("OSID", h->osid, sizeof h->osid);
    ret = SBCOK;

errdone:
    return ret;

}


SBCStatus SBC_BootModeFactory(VOID *blkhnd, VOID *ImageHandle)
{
  SBCStatus ret = SBCOK;
  
  UINTN startlba = 0;
  

  UINT32  imglen = SBC_RAWPRT_DFLT_BLK_SZ;
  UINT8   imghdr[SBC_RAWPRT_DFLT_BLK_SZ] = {0, };

  UINT8   *loadimg = NULL;
  

  [[maybe_unused]]EFI_HANDLE  *ssbl_img_hndl;
  [[maybe_unused]]UINTN endlba = 0;
  [[maybe_unused]]INTN       hndlcnt = 0;
  __attribute__((unused))EFI_STATUS retval;

  [[gnu::unused]]CHAR16 *fname = L"\\EFI\\BOOT\\SSBL.efi";


  [[gnu::unused]]LV_t wrlv;


  SBC_RET_VALIDATE_ERRCODEMSG((blkhnd != NULL), SBCNULLP, "Block I/O Handle Nill");

  startlba = ((BOOT_SECTOR3_OFS | BOOT_SSBL_OFS) >> SBC_RAWPRT_DFLT_SHIFT);

  ret = SBC_RawPrtReadBlock(blkhnd, (void *)imghdr, &imglen, startlba);
  if (ret != SBCOK) {
    //Print(L"SSBL Factory Block Read Fail \n");
    goto errdone;
  }

  CopyMem((void *)&imglen, &imghdr[0], sizeof imglen);

  dprint("Write SSBL Image  (Addr : 0x%lx) Start LBA : 0x%lx, Len : %ld (0x%lx)",
       (BOOT_SECTOR3_OFS | BOOT_SSBL_OFS), 
       startlba,
       imglen,
       imglen);
 

  dprint("Boot Service Allocate ");
  retval = gBS->AllocatePool(EfiBootServicesData, imglen, (VOID **)&loadimg);
  if (EFI_ERROR(retval)) {
    eprint("Faile to allocate memrory : %r", retval);
    ret = SBCNULLP;
    goto errdone;
  }

  retval = SBC_CopyBlockDeviceToFile(blkhnd,
                                     (BOOT_SECTOR3_OFS | BOOT_SSBL_OFS) + 4,
                                     imglen,
                                     fname,
                                     NULL);
  if (EFI_ERROR(retval)) {
    eprint("Factory SSBL File Create Fail : %r", retval);
    ret = SBCNOTFND;
    goto errdone;
  }
#ifndef _FSBL_TEST_
  if (tmp_prtheader->keymode != KEY_MODE_NORMAL) {
    tmp_prtheader->keymode = KEY_MODE_NORMAL;


    CopyMem(imghdr, tmp_prtheader, sizeof(rawprt_hdr_t));

  }
#endif 

  sys_end_time = SBC_PerfNowTicks();
  //dprint("sys_end_time : %ld (%ld)", sys_end_time, sys_end_time - sys_start_time);
  sys_ns_var  = SBC_PerfTicksTons(_PerfDeltaTicks(sys_start_time, sys_end_time));
  //dprint("sys_ns_var : %ld", sys_ns_var);

  SBC_LogElapsedTime(L"FSBL Boot Time", sys_ns_var);
  ret = SBC_SSBL_LoadAndStart(ImageHandle);
  if (ret != SBCOK) {
    //Print(L"SSBL Factory Running Fail \n");
    goto errdone;
  }

errdone:

  if (loadimg != NULL) {
    FreePool(loadimg);
  }



  return ret;

}


SBCStatus SBC_BootModeNormalAndpUdate(VOID *blkhnd, VOID *ImageHandle, UINTN nrombank)
{
  SBCStatus ret = SBCOK;
  
  UINTN startlba = 0;
  

  UINT32  imglen = SBC_RAWPRT_DFLT_BLK_SZ;
  UINT8   imghdr[SBC_RAWPRT_DFLT_BLK_SZ] = {0, };
  UINT8   *loadimg = NULL;
  UINTN   bsofs = 0; // Boot Sector Offset
  

  [[gnu::unused]] EFI_HANDLE  *ssbl_img_hndl;
  [[maybe_unused]]UINTN endlba = 0;
  [[maybe_unused]]INTN       hndlcnt = 0;
  __attribute__((unused))EFI_STATUS retval;
  [[gnu::unused]]CHAR16 *fname = L"\\EFI\\BOOT\\SSBL.efi";

  [[gnu::unused]]CHAR16 *fname1 = L"\\EFI\\BOOT\\SSBL.efi.bkp";
  [[maybe_unused]] int idx;



  [[gnu::unused]] LV_t wrlv;
  //UINT8 *imgssbl = NULL;
#ifdef _ALL_PASS_
  SBC_BootModeFactory(blkhnd, ImageHandle);
  return SBCOK;
#endif
  dprint("*** ----- Normal and Update Boot SSBL running ( Bank Id : 0x%x ) -----", nrombank);

  SBC_RET_VALIDATE_ERRCODEMSG((nrombank > 0 && nrombank < 3), SBCINVPARAM, "Invalid Parameter for SSBL bank");
  SBC_RET_VALIDATE_ERRCODEMSG((blkhnd != NULL), SBCNULLP, "Block I/O Handle Nill");

  bsofs = (BOOT_SECTOR1_OFS | ((nrombank - 1) << SBC_BOOTFW_BKN_OFS));
  startlba = ((bsofs | BOOT_SSBL_OFS) >> SBC_RAWPRT_DFLT_SHIFT);

  dprint("Running SSBL Info. addr : 0x%lx, Image Len : %ld ", (bsofs | BOOT_SSBL_OFS), imglen);

  ret = SBC_RawPrtReadBlock(blkhnd, (void *)imghdr, &imglen, startlba);
  if (ret != SBCOK) {
    eprint("Raw-Parttiion SSBL Image Not Found");
    goto errdone;
  }

  CopyMem((void *)&imglen, &imghdr[0], sizeof imglen);

  dprint("***** Running SSBL addr : 0x%lx, Image Len : %ld (0x%lx) **** ", 
         (bsofs | BOOT_SSBL_OFS), 
         imglen,
         imglen);
 
  //imglen = ALIGN_VALUE(imglen, SBC_RAWPRT_DFLT_BLK_SZ);
  //dprint("Boot Service Allocate ");
  retval = gBS->AllocatePool(EfiBootServicesData, imglen, (VOID **)&loadimg);
  if (EFI_ERROR(retval)) {
    eprint("Faile to allocate memrory : %r", retval);
    ret = SBCNULLP;
    goto errdone;
  }

  retval = SBC_CopyBlockDeviceToFile(blkhnd,
                                     (bsofs | BOOT_SSBL_OFS) + 4,
                                     imglen,
                                     fname,
                                     NULL);
  if (EFI_ERROR(retval)) {
    eprint("Factory SSBL File Create Fail");
    ret = SBCNOTFND;
    goto errdone;
  }

  sys_end_time = SBC_PerfNowTicks();
  //dprint("sys_end_time : %ld (%ld)", sys_end_time, sys_end_time - sys_start_time);
  sys_ns_var  = SBC_PerfTicksTons(_PerfDeltaTicks(sys_start_time, sys_end_time));
  //dprint("sys_ns_var : %ld", sys_ns_var);

  SBC_LogElapsedTime(L"FSBL Boot Time", sys_ns_var);

  ret = SBC_SSBL_LoadAndStart(ImageHandle);
  //SBC_GRUB_LoadAndStart(NULL); 
  if (ret != SBCOK) {
    //Print(L"SSBL  Running Fail \n");
    goto errdone;
  }
errdone:

  if (loadimg != NULL) {
    FreePool(loadimg);
  }



  return ret;

  
}

CHAR16 mrgmsg[8192]; 
static BOOLEAN _get_fw_bankid(UINT32 val, UINT32 *cur, UINT32 *prev)
{
    UINT8 bank_first;
    UINT8 bank_second;
    //BOOLEAN is_factory = FALSE;

    bank_first  = (UINT8)((val >> 8) & 0xFF);
    bank_second = (UINT8)((val >> 24) & 0xFF);

    if (bank_first == 'P' && bank_second == 'P') {
       return TRUE;
    }

    //Print(L"Banke First : %c , Bank Second : %c \n", bank_first, bank_second);

    if(bank_first == 'C') {
        *cur = (val) & 0xFF;
    }
    else if(bank_first == 'P') {
        *prev = (val) & 0xFF;
    }

    if(bank_second == 'C') {
        *cur = (val >> 16) & 0xFF;
    }
    else if(bank_second == 'P') {
        *prev = (val >> 16) & 0xFF;
    }

    return FALSE;

}

static EFI_STATUS SBC_DrveriInit(VOID)
{
extern EFI_STATUS SBC_LodaDriver(CONST CHAR16 *FileName, CONST BOOLEAN  Connect);
#define SERIAL_DXE_PATH                 L"\\EFI\\BOOT\\SerialDxe.efi"
#define FTDI_USB_SERIAL_DXE_PATH        L"\\EFI\\BOOT\\FtdiUsbSerialDxe.efi"
#define TERMINAL_DXE_PATH               L"\\EFI\\BOOT\\TerminalDxe.efi"
#define XFS64_PATH                      L"\\EFI\\BOOT\\xfs_x64.efi"
  EFI_STATUS retval = EFI_SUCCESS;
#ifdef _SBC_DRIVER_LOAD_
    retval = SBC_LodaDriver(SERIAL_DXE_PATH, TRUE);
    if (EFI_ERROR (retval)){
        sbc_err_sysprn(SBC_LOG_CMN_PRIO_INFO, 2,
                     SYS_LOG_HOST_BOOT,
                     SYS_LOG_APP_NAME,
                     SYS_LOG_CSC_NAME,
                     0,
                     L"Detection",
                     L"Failed to load the Serial Driver");
      //goto errdone;
    }
//  else {
//    sbc_err_sysprn(SBC_LOG_CMN_PRIO_INFO, 2,
//                 SYS_LOG_HOST_BOOT,
//                 SYS_LOG_APP_NAME,
//                 SYS_LOG_CSC_NAME,
//                 0,
//                 L"Detection",
//                 L"Loaded to the Serial Driver");
//  }

    //gBS->Stall(50000);   // 50ms 지연
    //sleep(1);

    retval = SBC_LodaDriver(FTDI_USB_SERIAL_DXE_PATH, TRUE);
    if (EFI_ERROR (retval)){
      //Print(L"FTDI_USB_SERIAL_DXE_PATH Dxe driver load fail \n");
      sbc_err_sysprn(SBC_LOG_CMN_PRIO_INFO, 2,
                 SYS_LOG_HOST_BOOT,
                 SYS_LOG_APP_NAME,
                 SYS_LOG_CSC_NAME,
                 0,
                 L"Detection",
                 L"Failed to load the FTDI USB Serial Driver");
      //goto errdone;
    }
//  else {
//    sbc_err_sysprn(SBC_LOG_CMN_PRIO_INFO, 2,
//                 SYS_LOG_HOST_BOOT,
//                 SYS_LOG_APP_NAME,
//                 SYS_LOG_CSC_NAME,
//                 0,
//                 L"Detection",
//                 L"Loaded to the FTDI USB Serial Driver");
//
//    //sleep(1);
//  }

    //gBS->Stall(50000);   // 50ms 지연
    retval = SBC_LodaDriver(TERMINAL_DXE_PATH, TRUE);
    if (EFI_ERROR (retval)){
      //Print(L"TERMINAL_DXE_PATH Dxe driver load fail \n");
      sbc_err_sysprn(SBC_LOG_CMN_PRIO_INFO, 2,
                 SYS_LOG_HOST_BOOT,
                 SYS_LOG_APP_NAME,
                 SYS_LOG_CSC_NAME,
                 0,
                 L"Detection",
                 L"Failed to load the Terminal Dxe Driver");
      ///goto errdone;
    }
//  else {
//
//    sbc_err_sysprn(SBC_LOG_CMN_PRIO_INFO, 2,
//                 SYS_LOG_HOST_BOOT,
//                 SYS_LOG_APP_NAME,
//                 SYS_LOG_CSC_NAME,
//                 0,
//                 L"Detection",
//                 L"Loaded to the Terminal Dxe Driver");
//
//    //sleep(1);
//  }

    //gBS->Stall(50000);   // 50ms 지연
    retval = SBC_LodaDriver(XFS64_PATH, TRUE);
    if (EFI_ERROR (retval)){
          sbc_err_sysprn(SBC_LOG_CMN_PRIO_INFO, 2,
                 SYS_LOG_HOST_BOOT,
                 SYS_LOG_APP_NAME,
                 SYS_LOG_CSC_NAME,
                 0,
                 L"Detection",
                 L"Failed to load the XF64 Driver");
      //goto errdone;
    }
//  else {
//    sbc_err_sysprn(SBC_LOG_CMN_PRIO_INFO, 2,
//                 SYS_LOG_HOST_BOOT,
//                 SYS_LOG_APP_NAME,
//                 SYS_LOG_CSC_NAME,
//                 0,
//                 L"Detection",
//                 L"Loaded to the XF64 Driver");
//
//    //sleep(3);
//  }
    //gBS->Stall(50000);   // 50ms 지연
#else
    if (retval != EFI_SUCCESS) {
        goto errdone;
    }
#endif

//errdone:
    return retval;
}


static void factory_md_abnormal_boot_state(VOID *priv)
{
    boot_proc_t *p = (boot_proc_t *)priv;

    SBC_BootKeyModeChange(BOOT_MODE_FACTORY, KEY_MODE_NORMAL, (VOID *)p);

    return;
}

VOID SBC_SelectSsblVerifyTarget(
    IN  const boot_proc_t *btproc,
    IN  UINT32             currbank_id,
    IN  UINT32             prevbank_id,
    OUT UINT32            *bank_id,
    OUT UINT32            *boot_mode
)
{
    /* Default: current bank / normal boot */
    *bank_id   = currbank_id;
    *boot_mode = BOOT_MODE_NORMAL;

    if (btproc->rcvmode == 1) {

        if (btproc->prevmode == 1) {
            dprint("Normal mode verify running on previous bank");
            *bank_id = prevbank_id;
            return;
        }

        if (btproc->prevmode == 0) {
            dprint("Normal mode verify running on factory bank");
            *boot_mode = BOOT_MODE_FACTORY;
            return;
        }
    }

    dprint("Normal mode verify running on current bank");
}

SBCStatus SBC_RunSsblNormalScenario(
    IN  boot_proc_t            *btproc,
    IN  EFI_BLOCK_IO_PROTOCOL  *h_blkio,
    IN  EFI_HANDLE              ImageHandle,
    IN  UINT32                  currbank_id,
    IN  UINT32                  prevbank_id
)
{
    SBCStatus ret;
    UINT32    bank_id    = currbank_id;
    BOOLEAN   is_factory = FALSE;

    /*
     * Decide target bank / mode
     */
    if (btproc->rcvmode == 1) {

        if (btproc->prevmode == 1) {
            dprint("Normal mode SSBL running on previous bank");
            bank_id = prevbank_id;

        } else if (btproc->prevmode == 0) {
            dprint("Normal mode SSBL running on factory bank");
            is_factory = TRUE;
        }
    }

    /*
     * Execute SSBL
     */
    if (is_factory == TRUE) {

        ret = SBC_BootModeFactory(
                  h_blkio,
                  ImageHandle
              );

    } else {

        if (bank_id == currbank_id) {
            dprint("Normal mode SSBL running on current bank");
        }

        ret = SBC_BootModeNormalAndpUdate(
                  h_blkio,
                  ImageHandle,
                  bank_id
              );
    }

    /*
     * Error handling
     */
    if (ret != SBCOK) {
        eprint("SSBL Boot Fail (ret=%d)", ret);
        btproc->bootst = SB_PROC_ST_ABNRAM;
        return ret;
    }

    return SBCOK;
}

extern EFI_STATUS SBC_LogFileInit( EFI_HANDLE        logHandle);
extern EFI_STATUS MapRebuild(VOID);
extern VOID PrintMappingTable();
extern SBCStatus
SBC_DeleteFileOnMyBootFs(
    IN CHAR16 *FilePath
);


#ifdef _RUN_GCS_

#include <Library/IoLib.h>
#include <Library/DebugLib.h>


#define SBC_IA32_APIC_BASE_MSR          0x1B
#define SBC_APIC_BASE_ENABLE            BIT11
#define SBC_APIC_BASE_MASK              0xFFFFF000ULL

#define SBC_APIC_SVR                    0x0F0
#define SBC_APIC_LVTT                   0x320
#define SBC_APIC_TMICT                  0x380
#define SBC_APIC_TMCCT                  0x390
#define SBC_APIC_TDCR                   0x3E0

#define SBC_APIC_SOFTWARE_ENABLE        BIT8
#define SBC_APIC_TIMER_MASKED           BIT16
#define SBC_APIC_TIMER_PERIODIC         BIT17

#define SBC_APIC_TIMER_VECTOR           0xEF
#define SBC_APIC_SPURIOUS_VECTOR        0xFF
#define SBC_APIC_TIMER_DIVIDE_BY_16     0x3
#define SBC_APIC_TIMER_INIT_COUNT       0xFFFFFFFFU

STATIC UINTN
SBC_EFI_GetApicBase(
    VOID
)
{
    UINT64 ApicBaseMsr;

    ApicBaseMsr = AsmReadMsr64(SBC_IA32_APIC_BASE_MSR);

    if ((ApicBaseMsr & SBC_APIC_BASE_ENABLE) == 0) {
        return 0;
    }

    return (UINTN)(ApicBaseMsr & SBC_APIC_BASE_MASK);
}

STATIC BOOLEAN
SBC_EFI_InitLocalApicTimer(
    VOID
)
{
    UINTN  ApicBase;
    UINT32 Value;
    UINT32 InitCount;
    UINT32 CurrentCount;

    ApicBase = SBC_EFI_GetApicBase();
    if (ApicBase == 0) {
        DEBUG((DEBUG_ERROR, "[FSBL] invalid Local APIC base\n"));
        return FALSE;
    }

    /*
     * Enable Local APIC by setting Software Enable bit in SVR.
     */
    Value = MmioRead32(ApicBase + SBC_APIC_SVR);
    Value |= SBC_APIC_SOFTWARE_ENABLE;
    Value = (Value & ~0xFFU) | SBC_APIC_SPURIOUS_VECTOR;
    MmioWrite32(ApicBase + SBC_APIC_SVR, Value);

    /*
     * Set APIC timer divide configuration.
     */
    MmioWrite32(
        ApicBase + SBC_APIC_TDCR,
        SBC_APIC_TIMER_DIVIDE_BY_16
    );

    /*
     * Configure APIC timer as periodic and masked.
     * Masked means it will not generate interrupt.
     * TimerLib only needs the counter value.
     */
    MmioWrite32(
        ApicBase + SBC_APIC_LVTT,
        SBC_APIC_TIMER_MASKED |
        SBC_APIC_TIMER_PERIODIC |
        SBC_APIC_TIMER_VECTOR
    );

    /*
     * This is the key point.
     * InternalX86GetInitTimerCount() reads this register.
     */
    MmioWrite32(
        ApicBase + SBC_APIC_TMICT,
        SBC_APIC_TIMER_INIT_COUNT
    );

    InitCount = MmioRead32(ApicBase + SBC_APIC_TMICT);
    CurrentCount = MmioRead32(ApicBase + SBC_APIC_TMCCT);

    DEBUG((
        DEBUG_INFO,
        "[FSBL] APIC timer init: ApicBase=0x%lx, InitCount=0x%x, CurrentCount=0x%x\n",
        (UINT64)ApicBase,
        InitCount,
        CurrentCount
    ));

    return (InitCount != 0);
}
#endif

EFI_STATUS
EFIAPI
UefiMain (
//EntryPoint(
  IN EFI_HANDLE        ImageHandle,
  IN EFI_SYSTEM_TABLE  *SystemTable
  )
{



    atp_ident_t diceid;
    EFI_STATUS retval = EFI_SUCCESS;
    SBCStatus  ret = SBCOK;
    rawprt_hdr_t h_rawprtheader;    // Raw Partition Header handle
    UINT32 pres_low = 0;
    UINT32 currbank_id = 0;
    UINT32 prevbank_id = 0;
    __attribute__((unused)) UINT32 bootmd = 0; // Boot Mode
    LV_t baseansr;
    [[maybe_unused]] UINTN testid = 0xAA55AA55;

    [[gnu::unused]] EFI_HANDLE ssbl_img_hndl = NULL;

    unit_proc_t btproc;

    UINTN driver_load_ns = 0ULL;

    //
    // Added by Leon
    // For Hardware read fail
    //
#ifdef _RUN_GCS_
    SBC_EFI_InitLocalApicTimer();
#endif

    sys_start_time = SBC_PerfNowTicks();

    SBC_TIME_BLOCKS_NS (driver_load_ns,
        { retval = SBC_DrveriInit(); });


    ret = SBC_DeleteFile(EFI_BOOT_SSBL_PATH);
    
     if (ret == SBCNOTFND) {
             sbc_err_sysprn(SBC_LOG_CMN_PRIO_INFO, 2,
                  SYS_LOG_HOST_BOOT,
                  SYS_LOG_APP_NAME,
                  SYS_LOG_CSC_NAME,
                  0,
                  L"Detetion",
                  L"GCS_VENDOR_SP Can not found \\EFI\\BOOT\\SSBL.efi \n");
     }

     if ((ret != SBCOK) && (ret != SBCNOTFND )) {
             sbc_err_sysprn(SBC_LOG_CMN_PRIO_ERR, 2,
                  SYS_LOG_HOST_BOOT,
                  SYS_LOG_APP_NAME,
                  SYS_LOG_CSC_NAME,
                  0,
                  L"Detetion",
                  L"GCS_VENDOR_SP Failed to delete the \\EFI\\BOOT\\SSBL.efi \n");
             //goto errdone;
     }

     sbc_err_sysprn(SBC_LOG_CMN_PRIO_INFO, 2,
                  SYS_LOG_HOST_BOOT,
                  SYS_LOG_APP_NAME,
                  SYS_LOG_CSC_NAME,
                  0,
                  L"Detetion",
                  L"GCS_VENDOR_SP Success to delete the \\EFI\\BOOT\\SSBL.efi \n");

    retval =  MapRebuild();
    if (EFI_ERROR(retval)) {
      sbc_err_sysprn(SBC_LOG_CMN_PRIO_INFO, 2,
                 SYS_LOG_HOST_BOOT,
                 SYS_LOG_APP_NAME,
                 SYS_LOG_CSC_NAME,
                 0,
                 L"Detetion",
                 L"GCS_VENDOR_SP Faile to Reconnect to All controller \n");
    }
    else {
      sbc_err_sysprn(SBC_LOG_CMN_PRIO_INFO, 2,
                 SYS_LOG_HOST_BOOT,
                 SYS_LOG_APP_NAME,
                 SYS_LOG_CSC_NAME,
                 0,
                 L"Detetion",
                 L"GCS_VENDOR_SP Success to Reconnect to All controller \n");
    }

#ifdef _LOG_RECODING_
    SBC_LogInitAuto(&gLogCtx,
                    ImageHandle,
                    FSBL_LOG_PATH,
                    SBC_LOG_DEFAULT_BUF_SIZE,
                    NULL);
#endif

    //SBC_SetLogWriteCtxHndl((VOID *)&gLogCtx);


//#ifdef _DEBUG_PRINT_ON_
//    PrintMappingTable();
//#endif

    SBC_LogElapsedTime(L"GCS Driver Load", driver_load_ns);
    sbc_err_sysprn(SBC_LOG_CMN_PRIO_INFO, 2,
                 SYS_LOG_HOST_BOOT,
                 SYS_LOG_APP_NAME,
                 SYS_LOG_CSC_NAME,
                 0,
                 L"Detetion",
                 L"GCS_VENDOR_SP FSBL Statring");

    btproc.bootst = TRUE;

    ZeroMem(&btproc, sizeof btproc);
    ZeroMem(&h_rawprtheader, sizeof h_rawprtheader);

#ifdef _SBC_TPM_

    retval = SBC_TpmInit();
    if (EFI_ERROR(retval)) {
        sbc_err_sysprn(SBC_LOG_CMN_PRIO_INFO, 2,
                     SYS_LOG_HOST_BOOT,
                     SYS_LOG_APP_NAME,
                     SYS_LOG_CSC_NAME,
                     0,
                     L"Detetion",
                     L"GCS_VENDOR_SP TPM Init not OK \n");

        goto errdone;
    }

    sbc_err_sysprn(SBC_LOG_CMN_PRIO_INFO, 2,
                     SYS_LOG_HOST_BOOT,
                     SYS_LOG_APP_NAME,
                     SYS_LOG_CSC_NAME,
                     0,
                     L"Detetion",
                     L"GCS_VENDOR_SP TPM Init OK \n");

    //retval= SBC_DumpTpmFixedProperties();
    retval = SBC_PrintTpmVersionInfo();
    if (EFI_ERROR(retval)) {
        sbc_err_sysprn(SBC_LOG_CMN_PRIO_INFO, 2,
                     SYS_LOG_HOST_BOOT,
                     SYS_LOG_APP_NAME,
                     SYS_LOG_CSC_NAME,
                     0,
                     L"Detetion",
                     L"GCS_VENDOR_SP TPM Version Not found \n");

        goto errdone;
    }

    sbc_err_sysprn(SBC_LOG_CMN_PRIO_INFO, 2,
                     SYS_LOG_HOST_BOOT,
                     SYS_LOG_APP_NAME,
                     SYS_LOG_CSC_NAME,
                     0,
                     L"Detetion",
                     L"GCS_VENDOR_SP TPM Version found \n");
#if 0
    UINT8      RandBuf[512];
    UINT8      RdBuf[512] = {0,};
    UINT16     RdSize = 0;
    for (int rndlp = 0; rndlp < 1; rndlp++) {
        retval = SBC_TpmGetRandom(RandBuf, sizeof(RandBuf));
        SBC_external_mem_print_bin("TPM Random", RandBuf, sizeof(RandBuf));
    }

    const SBC_NV_SLOT *osid_slot = SBC_NvFindSlotByName("OS ID Key");
    dprint("Slock Name : %a", osid_slot->Name);
    dprint("Slock Index : 0x%08lx", osid_slot->Index);
    dprint("Slock Size : %d", osid_slot->Size);

    retval = SBC_NvWriteChecked(osid_slot,
                                RandBuf,
                                64,
                                0);
   
    retval = SBC_NvReadBuffer(osid_slot,
                              RdBuf,
                              osid_slot->Size,
                              &RdSize);

    SBC_mem_print_bin("OSID NVKEY", RdBuf, RdSize);


    return EFI_SUCCESS;
#endif
#endif

    btproc.bootst = SB_PROC_ST_NRMA;
    // Get the NVMe SSD Raw Partiton handle and Header information
    ret = SBC_BlkIoHandleInit(&h_blkio, &h_rawprtheader);
    if (ret != SBCOK) {
      sbc_err_sysprn(SBC_LOG_CMN_PRIO_INFO, 2,
                 SYS_LOG_HOST_BOOT,
                 SYS_LOG_APP_NAME,
                 SYS_LOG_CSC_NAME,
                 0,
                 L"Detetion",
                 L"GCS_VENDOR_SP Block I/O Init Fail");
      SBC_ShutdownSystem(); 
      //goto errdone;
    }

    tmp_prtheader = &h_rawprtheader;
    // Check the Preference SSBL bank
    CopyMem((void *)&pres_low, (void *)&h_rawprtheader.bootpres[0], 4);

    btproc.is_factory = _get_fw_bankid(pres_low, &currbank_id, &prevbank_id);

    dprint("Pres Low : 0x%04x Cur. Bank ID : %d , Prev. Bank ID : %d , IS_FACTTORY : %b", 
           pres_low, currbank_id, prevbank_id, btproc.is_factory);

    btproc.curr_sw_bnk = currbank_id;
    btproc.pvs_sw_bnk = prevbank_id;
    btproc.bm = h_rawprtheader.bootmode;
    btproc.km = h_rawprtheader.keymode;
    btproc.curr_sw_bnk = currbank_id;
    btproc.pvs_sw_bnk = prevbank_id;
    btproc.blkhnd = h_blkio;
    btproc.keyinfo = (VOID *)&diceid;
    btproc.rawprt_hdr = &h_rawprtheader;
    btproc.baseansr = (void *)&baseansr;
    btproc.imghndl = ImageHandle;
    btproc.prevmode = h_rawprtheader.prevmode;

    dprint("Prev. Mode is %d", btproc.prevmode);

    //extern VOID SBC_HardWareInfoReadFailed(VOID *handle);
    //SBC_HardWareInfoReadFailed((VOID *)&btproc); 


    
    //
    // Added by Leon
    // Run from Recovry Mode 
    //
    btproc.rcvmode = h_rawprtheader.rcvmode;
    btproc.b_forced = FALSE;

    tmp_btproc = &btproc;

    dprint("Boot Mode is %d", h_rawprtheader.bootmode);
    ZeroMem(mrgmsg, sizeof mrgmsg);
    UnicodeSPrint(mrgmsg, sizeof mrgmsg, L"GCS_SP_FW FSBL Boot Mode (0x%x) And Key Mode (0x%x) Recovery Mode (0x%x) \n", 
                  btproc.bm, btproc.km, btproc.rcvmode);

    sbc_err_sysprn(SBC_LOG_CMN_PRIO_INFO, 2,
                     SYS_LOG_HOST_BOOT,
                     SYS_LOG_APP_NAME,
                     SYS_LOG_CSC_NAME,
                     8,
                     L"Information",
                     mrgmsg);

    dprint("Boot Mode : %d , Key Mode : %d, Recovery Mode : %d, Prev : %d",
           btproc.bm, btproc.km, h_rawprtheader.rcvmode,h_rawprtheader.prevmode);

#ifdef _SHELL_CMD_LINE_
    dprint("Shell Execute");
    ParseShellOptions((VOID *)&btproc);
    return EFI_SUCCESS;
#endif
   // Step 1-1 )  FSBL, self sign and verify
    SBC_AntiTamperingInit(NULL);

    //return EFI_SUCCESS; 

#ifndef _SHELL_CMD_LINE_
    ret = SBC_FSBL_Verify(h_blkio, 
                          &baseansr, 
                          currbank_id, 
                          h_rawprtheader.bootmode, 
                          STR_FSBL_F_NAME);
    if (ret != SBCOK) {
          sbc_err_sysprn(SBC_LOG_CMN_PRIO_ERR, 2,
                 SYS_LOG_HOST_BOOT,
                 SYS_LOG_APP_NAME,
                 SYS_LOG_CSC_NAME,
                 8,
                 SYS_LOG_EVT_DETECTION,
                 L"GCS_tamper_FSBL signature verification failed\n");
          retval = EFI_INVALID_PARAMETER;
          if (h_rawprtheader.bootmode  == BOOT_MODE_NORMAL) {
              btproc.b_forced = TRUE;
          }
          btproc.bootst = SB_PROC_ST_ABNRAM;
#ifndef _ALL_PASS_
          goto errdone;
#endif

    }
#endif

    ZeroMem(mrgmsg, sizeof mrgmsg);
    ret = SBC_DiceKeysGen(ImageHandle, &diceid, currbank_id, h_rawprtheader.bootmode);
    if (ret != SBCOK) {
        sbc_err_sysprn(SBC_LOG_CMN_PRIO_ERR, 2,
             SYS_LOG_HOST_BOOT,
             SYS_LOG_APP_NAME,
             SYS_LOG_CSC_NAME,
             1,
             SYS_LOG_EVT_DETECTION,
             L"GCS_Dice_Key HW&SW Base Key Creation Fail");
        retval = EFI_INVALID_PARAMETER;
        btproc.bootst = SB_PROC_ST_ABNRAM;
          if (h_rawprtheader.bootmode  == BOOT_MODE_NORMAL) {
              btproc.b_forced = TRUE;
          }
#ifndef _ALL_PASS_
        goto errdone;
#endif
    }

    btproc.dice = (VOID *)&diceid;

    switch (h_rawprtheader.bootmode) {
    case BOOT_MODE_NORMAL:
        dprint("Boot Mode is BOOT_MODE_NORMAL");
        UINT32 bank_id;
        UINT32 boot_mode;

        SBC_SelectSsblVerifyTarget( &btproc,
                                    currbank_id,
                                    prevbank_id,
                                    &bank_id,
                                    &boot_mode);

        ret = SBC_SSBL_Verify(
                  h_blkio,
                  NULL,
                  bank_id,
                  boot_mode,
                  STR_SSBL_F_NAME
              );

        if (ret != SBCOK) {
          sbc_err_sysprn(SBC_LOG_CMN_PRIO_ERR, 2,
                     SYS_LOG_HOST_BOOT,
                     SYS_LOG_APP_NAME,
                     SYS_LOG_CSC_NAME,
                     8,
                     SYS_LOG_EVT_DETECTION,
                     L"GCS_tamper_SSBL signature verification failed");

          btproc.bootst = SB_PROC_ST_ABNRAM;
          if (h_rawprtheader.bootmode  == BOOT_MODE_NORMAL) {
              btproc.b_forced = TRUE;
          }
          retval = EFI_INVALID_PARAMETER;
#ifndef _ALL_PASS_
          goto errdone;
#endif
        }

        sbc_err_sysprn(SBC_LOG_CMN_PRIO_INFO, 2,
                     SYS_LOG_HOST_BOOT,
                     SYS_LOG_APP_NAME,
                     SYS_LOG_CSC_NAME,
                     8,
                     SYS_LOG_EVT_VALIDATION,
                     L"GCS_tamper_SSBL signature verification suuccess");

        ret =  SBC_DeviceIdKyeVerify(h_blkio, diceid.devid, diceid.osid);
        if (ret != SBCOK) {
          sbc_err_sysprn(SBC_LOG_CMN_PRIO_ERR, 2,
                     SYS_LOG_HOST_BOOT,
                     SYS_LOG_APP_NAME,
                     SYS_LOG_CSC_NAME,
                     8,
                     L"EVT",
                     L"GCS_Dice_Verify Failed to Device ID verify");
          retval = EFI_INVALID_PARAMETER;
          btproc.bootst = SB_PROC_ST_ABNRAM;
          if (h_rawprtheader.bootmode  == BOOT_MODE_NORMAL) {
              btproc.b_forced = TRUE;
          }
#ifndef _ALL_PASS_
          goto errdone;
#endif
        }

        sbc_err_sysprn(SBC_LOG_CMN_PRIO_INFO, 2,
             SYS_LOG_HOST_BOOT,
             SYS_LOG_APP_NAME,
             SYS_LOG_CSC_NAME,
             8,
             SYS_LOG_EVT_VALIDATION,
             L"GCS_Integrity_All boot components passed signature verification \n");

        ret = SBC_RunSsblNormalScenario(
                &btproc,
                h_blkio,
                ImageHandle,
                currbank_id,
                prevbank_id
        );

        if (ret != SBCOK) {
                retval = EFI_INVALID_PARAMETER;
          if (h_rawprtheader.bootmode == BOOT_MODE_NORMAL) {
              btproc.b_forced = TRUE;
          }
            #ifndef _ALL_PASS_
                goto errdone;
            #endif
        }
      break;
    case BOOT_MODE_FACTORY:
      //Print(L"Factory Boot Mode !!! \n");

#ifdef _SBC_DEVID_VERIFY_
      ret = SBC_SSBL_Verify(h_blkio, NULL, currbank_id, BOOT_MODE_FACTORY, STR_SSBL_F_NAME);
      dprint();
      if (ret != SBCOK) {
            sbc_err_sysprn(SBC_LOG_CMN_PRIO_ERR, 2,
                     SYS_LOG_HOST_BOOT,
                     SYS_LOG_APP_NAME,
                     SYS_LOG_CSC_NAME,
                     8,
                     SYS_LOG_EVT_DETECTION,
                     L"GCS_tamper_SSBL signature verification failed");
            btproc.bootst = SB_PROC_ST_ABNRAM;
            //btproc.b_forced = TRUE;
            retval = EFI_INVALID_PARAMETER;
            factory_md_abnormal_boot_state(&btproc);
#ifndef _ALL_PASS_
          goto errdone;
#endif
      }

      sbc_err_sysprn(SBC_LOG_CMN_PRIO_INFO, 2,
                     SYS_LOG_HOST_BOOT,
                     SYS_LOG_APP_NAME,
                     SYS_LOG_CSC_NAME,
                     8,
                     SYS_LOG_EVT_VALIDATION,
                     L"GCS_tamper_SSBL signature verification suuccess");

      
      SBC_OSID_KeyStore((void *)&btproc);

      ret =  SBC_DeviceIdKyeVerify(h_blkio, diceid.devid, diceid.osid);
      //ret = SBCOK;
      if (ret != SBCOK) {
          sbc_err_sysprn(SBC_LOG_CMN_PRIO_ERR, 2,
                     SYS_LOG_HOST_BOOT,
                     SYS_LOG_APP_NAME,
                     SYS_LOG_CSC_NAME,
                     8,
                     SYS_LOG_EVT_DETECTION,
                     L"GCS_Dice_Verify Failed to Device ID verify");

          factory_md_abnormal_boot_state(&btproc);
          retval = EFI_INVALID_PARAMETER;
          btproc.bootst = SB_PROC_ST_ABNRAM;
          if (h_rawprtheader.bootmode == BOOT_MODE_NORMAL) {
              btproc.b_forced = TRUE;
          }
#ifndef _ALL_PASS_
          goto errdone;
#endif
      }


      sbc_err_sysprn(SBC_LOG_CMN_PRIO_INFO, 2,
             SYS_LOG_HOST_BOOT,
             SYS_LOG_APP_NAME,
             SYS_LOG_CSC_NAME,
             8,
             SYS_LOG_EVT_VALIDATION,
             L"GCS_Integrity_All boot components passed signature verification \n");
#endif     

      ret = SBC_BootModeFactory(h_blkio, ImageHandle);
      if (ret != SBCOK) {
          eprint("BOOT_MODE_FACTORY Boot Fail");
          factory_md_abnormal_boot_state(&btproc);
          retval = EFI_INVALID_PARAMETER;
          btproc.bootst = SB_PROC_ST_ABNRAM;
#ifndef _ALL_PASS_
          goto errdone;
#endif
      }
      break;
    case BOOT_MODE_UPDATE:
#ifdef _SBC_DEVID_VERIFY_

      ret = SBC_SSBL_Verify(h_blkio, NULL, currbank_id, BOOT_MODE_UPDATE, STR_SSBL_F_NAME);
      if (ret != SBCOK) {
            sbc_err_sysprn(SBC_LOG_CMN_PRIO_ERR, 2,
                     SYS_LOG_HOST_BOOT,
                     SYS_LOG_APP_NAME,
                     SYS_LOG_CSC_NAME,
                     8,
                     SYS_LOG_EVT_DETECTION,
                     L"GCS_tamper_SSBL signature verification failed");
            btproc.bootst = SB_PROC_ST_ABNRAM;
          if (h_rawprtheader.bootmode == BOOT_MODE_NORMAL) {
              btproc.b_forced = TRUE;
          }
            retval = EFI_INVALID_PARAMETER;
#ifndef _ALL_PASS_
          goto errdone;
#endif
      }

      sbc_err_sysprn(SBC_LOG_CMN_PRIO_INFO, 2,
                     SYS_LOG_HOST_BOOT,
                     SYS_LOG_APP_NAME,
                     SYS_LOG_CSC_NAME,
                     8,
                     SYS_LOG_EVT_VALIDATION,
                     L"GCS_tamper_SSBL signature verification suuccess");
#if 1
      ret =  SBC_DeviceIdKyeVerify(h_blkio, diceid.devid, diceid.migid);
      if (ret != SBCOK) {
          sbc_err_sysprn(SBC_LOG_CMN_PRIO_ERR, 2,
                     SYS_LOG_HOST_BOOT,
                     SYS_LOG_APP_NAME,
                     SYS_LOG_CSC_NAME,
                     8,
                     L"Detection",
                     L"GCS_Dice_Verify Failed to Device ID verify");
          retval = EFI_INVALID_PARAMETER;
          //btproc.b_forced = TRUE;
          btproc.bootst = SB_PROC_ST_ABNRAM;
#ifndef _ALL_PASS_
          goto errdone;
#endif
      }
#endif

      // added by heappy at 20260429 
      // whenever update, check the bsaseanswer integrity check 
//    ret = SBC_BaseAnswerValidate(h_blkio, baseansr.value, baseansr.length, diceid.osid, BASE_ANS_KEY_STR);
//    if (ret != SBCOK) {
//        sbc_err_sysprn(SBC_LOG_CMN_PRIO_ERR, 2,
//                       SYS_LOG_HOST_BOOT,
//                       SYS_LOG_APP_NAME,
//                       SYS_LOG_CSC_NAME,
//                       8,
//                       L"Detection",
//                       L"GCS_tamper_OSID derived answer mismatched known answer");
//        btproc.bootst = SB_PROC_ST_ABNRAM;
//        goto errdone;
//    }



      sbc_err_sysprn(SBC_LOG_CMN_PRIO_INFO, 2,
             SYS_LOG_HOST_BOOT,
             SYS_LOG_APP_NAME,
             SYS_LOG_CSC_NAME,
             8,
             SYS_LOG_EVT_VALIDATION,
             L"GCS_Integrity_All boot components passed signature verification \n");
#endif     
      ret = SBC_BootModeNormalAndpUdate(h_blkio, ImageHandle, currbank_id);
      if (ret != SBCOK) {
          eprint("BOOT_MODE_UPDATE Boot Fail");
          retval = EFI_INVALID_PARAMETER;
          btproc.bootst = SB_PROC_ST_ABNRAM;
          if (h_rawprtheader.bootmode == BOOT_MODE_NORMAL) {
              btproc.b_forced = TRUE;
          }
#ifndef _ALL_PASS_
          goto errdone;
#endif
      }

      break;
    case BOOT_MODE_RECOVERY:

#ifdef _SBC_DEVID_VERIFY_

      ret = SBC_SSBL_Verify(h_blkio, NULL, prevbank_id, BOOT_MODE_RECOVERY, STR_SSBL_F_NAME);
      if (ret != SBCOK) {
            sbc_err_sysprn(SBC_LOG_CMN_PRIO_ERR, 2,
                     SYS_LOG_HOST_BOOT,
                     SYS_LOG_APP_NAME,
                     SYS_LOG_CSC_NAME,
                     8,
                     SYS_LOG_EVT_DETECTION,
                     L"GCS_tamper_SSBL signature verification failed");
            btproc.bootst = SB_PROC_ST_ABNRAM;
            //btproc.b_forced = TRUE;
            retval = EFI_INVALID_PARAMETER;
#ifndef _ALL_PASS_
          goto errdone;
#endif
      }

      sbc_err_sysprn(SBC_LOG_CMN_PRIO_INFO, 2,
                     SYS_LOG_HOST_BOOT,
                     SYS_LOG_APP_NAME,
                     SYS_LOG_CSC_NAME,
                     8,
                     SYS_LOG_EVT_VALIDATION,
                     L"GCS_tamper_SSBL signature verification suuccess");

     ret =  SBC_DeviceIdKyeVerify(h_blkio, diceid.devid, diceid.migid);
     if (ret != SBCOK) {
          sbc_err_sysprn(SBC_LOG_CMN_PRIO_ERR, 2,
                     SYS_LOG_HOST_BOOT,
                     SYS_LOG_APP_NAME,
                     SYS_LOG_CSC_NAME,
                     8,
                     SYS_LOG_EVT_DETECTION,
                     L"GCS_Dice_Verify Failed to Device ID verify");
             retval = EFI_INVALID_PARAMETER;
          if (h_rawprtheader.bootmode == BOOT_MODE_NORMAL) {
              btproc.b_forced = TRUE;
          }
             btproc.bootst = SB_PROC_ST_ABNRAM;
#ifndef _ALL_PASS_
          goto errdone;
#endif
     }

    sbc_err_sysprn(SBC_LOG_CMN_PRIO_INFO, 2,
             SYS_LOG_HOST_BOOT,
             SYS_LOG_APP_NAME,
             SYS_LOG_CSC_NAME,
             8,
             SYS_LOG_EVT_VALIDATION,
             L"GCS_Integrity_All boot components passed signature verification \n");
#endif  

      // Previously Boot FW loading 
      ret = SBC_BootModeNormalAndpUdate(h_blkio, ImageHandle, prevbank_id);
      if (ret != SBCOK) {
          eprint("BOOT_MODE_RECOVERY Boot Fail");
          retval = EFI_INVALID_PARAMETER;
          btproc.bootst = SB_PROC_ST_ABNRAM;
#ifndef _ALL_PASS_
          goto errdone;
#endif
      }
      break;
    default:
      //Print(L"Unknown (%d)  Boot Mode ... SHOULD go to Abort\n",h_rawprtheader.bootmode);
      btproc.bootst = SB_PROC_ST_ABNRAM;
      break;
    }


    //ret = SBC_FSBL_Verify(h_blkio, &baseansr);

  // Read SSBL from



  // Access bank addr ( (0x200 + (128 << 20)) * currbank_id )


errdone:

    sys_end_time = SBC_PerfNowTicks();
    //dprint("sys_end_time : %ld (%ld)", sys_end_time, sys_end_time - sys_start_time);
    sys_ns_var  = SBC_PerfTicksTons(_PerfDeltaTicks(sys_start_time, sys_end_time));
    //dprint("sys_ns_var : %ld", sys_ns_var);

    SBC_LogElapsedTime(L"FSBL Boot Time", sys_ns_var);
#ifndef _ALL_PASS_
    switch(h_rawprtheader.bootmode) {
    case BOOT_MODE_NORMAL:
    case BOOT_MODE_UPDATE:
    case BOOT_MODE_RECOVERY:

        if (btproc.b_forced == TRUE) {
            SBC_ShutdownSystem();

        }

        dprint("On FSBL, Normal and Update Mode processing~~~");
        if (btproc.bootst  == SB_PROC_ST_ABNRAM) {
            SBC_SecureBootUpdateScenario(&btproc);
        }
        
        break;

    case BOOT_MODE_FACTORY:

        if (btproc.b_forced == TRUE) {
            SBC_ShutdownSystem();

        }
        // In terms of the Abnormal behavior on Factory Mode
        if ((btproc.bootst != SB_PROC_ST_ABNRAM)) {
                  // Change the key mode to normal based on key mode behavior scenario.
            if (tmp_prtheader->keymode != KEY_MODE_NORMAL) {
                tmp_prtheader->keymode = KEY_MODE_NORMAL;

                SBC_RawPrtBlockWrite(h_blkio, (UINT8 *)&tmp_prtheader, sizeof(rawprt_hdr_t), 0);
            }


        }
        else {
            sbc_err_sysprn(SBC_LOG_CMN_PRIO_INFO, 2,
                 SYS_LOG_HOST_BOOT,
                 SYS_LOG_APP_NAME,
                 SYS_LOG_CSC_NAME,
                 8,
                 SYS_LOG_EVT_VALIDATION,
                 L"GCS_tamper_Factory firmware integrity is compromised and System Shutdown\n");
        }


        
    default:
        break;
    }


    SBC_ShutdownSystem();
#else 
    SBC_BootModeFactory(h_blkio, ImageHandle);
#endif
    return retval;
}

