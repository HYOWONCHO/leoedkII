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
#include "SBC_BootProc.h"
#include "SBC_SystemControl.h"
#include "SBC_ProtectedSW.h"
#include "SBC_Hashing.h"
#include "SBC_Nvram.h"
#include "SBC_TypeDefs.h"

extern SBCStatus SBC_GRUB_LoadAndStart(EFI_HANDLE ImageHandle);
extern SBCStatus SBC_BootKeyModeChange(UINT32 newbm, UINT32 newkey, VOID *priv);

//EFI_HANDLE h_sbchandle;

UINTN   sys_start_time = 0ULL;
UINTN   sys_end_time = 0ULL;
UINTN   sys_ns_var = 0ULL;

static boot_proc_t       btproc;

VOID *h_blkio;               // Block I/O handle
CHAR16 mrgmsg[8192];

extern SBCStatus SBC_SSBL_LoadAndStart(EFI_HANDLE ImageHandle);

#ifdef LEO_EMUPKG
RETURN_STATUS EFIAPI SerialPortInitialize(VOID)
{
  RETURN_STATUS ret = RETURN_SUCCESS;

  UINT64              BaudRate;
  UINT32              ReceiveFifoDepth;
  EFI_PARITY_TYPE     Parity;
  UINT8               DataBits;
  EFI_STOP_BITS_TYPE  StopBits;

  BaudRate         = FixedPcdGet64 (PcdUartDefaultBaudRate);
  ReceiveFifoDepth = 0;         // Use default FIFO depth
  Parity           = (EFI_PARITY_TYPE)FixedPcdGet8 (PcdUartDefaultParity);
  DataBits         = FixedPcdGet8 (PcdUartDefaultDataBits);
  StopBits         = (EFI_STOP_BITS_TYPE)FixedPcdGet8 (PcdUartDefaultStopBits);


  dprint("----- SerialProtInitialize -----");
  dprint("Baud Rate : %d", BaudRate);
  dprint("ReceiveFifoDepth : %d", ReceiveFifoDepth);
  dprint("Parity : %d", (UINT32)Parity);
  dprint("DataBits : %d", (UINT32)DataBits);
  dprint("StopBits : %d", (UINT32)StopBits);

  return ret;
}
#endif



SBCStatus  SBC_DiceKeysGen(EFI_HANDLE ImageHandle, VOID *p,UINTN normbank, UINTN bm)
{
    SBCStatus ret = SBCOK;
    atp_ident_t *h = NULL;

    h = (atp_ident_t *)p;

    ret = SBC_GenDeviceID(h->devid);
    if (ret != SBCOK) {
        dprint("Device ID generate fail \n");
        goto errdone;
    }

    //SBC_mem_print_bin("Device ID", h->devid, sizeof h->devid);SBC_mem_print_bin("Device ID", h->devid, sizeof h->devid);




    ret = SBC_GenFWID(ImageHandle, h->devid, h->fwid, normbank, bm);
    if (ret != SBCOK) {
        dprint("FW ID generate fail \n");
        goto errdone;
    }

    //SBC_mem_print_bin("Firmware ID", h->fwid, sizeof h->fwid);

    ret = SBC_GenOSID(ImageHandle,  h->fwid, h->osid);
    if (ret != SBCOK) {
        dprint("FW ID generate fail \n");
        goto errdone;
    }

    //SBC_mem_print_bin("Firmware ID", h->fwid, sizeof h->fwid);
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
  

  EFI_HANDLE  *ssbl_img_hndl;
  [[maybe_unused]]UINTN endlba = 0;
  [[maybe_unused]]INTN       hndlcnt = 0;
  __attribute__((unused))EFI_STATUS retval;
  [[gnu::unused]]CHAR16 *fname = EFI_BOOT_SSBL_PATH;


  LV_t wrlv;
  //UINT8 *imgssbl = NULL;

  SBC_RET_VALIDATE_ERRCODEMSG((blkhnd != NULL), SBCNULLP, "Block I/O Handle Nill");

  startlba = ((BOOT_SECTOR3_OFS | BOOT_SSBL_OFS) >> SBC_RAWPRT_DFLT_SHIFT);
  //Print("Start LBA Address : 0x%x  \n")
  //endlba = (BOOT_SSBL_MAX >>  SBC_RAWPRT_DFLT_SHIFT) - startlba;

  //dprint("Start Addr : 0x%lx , End addr : 0x%lx \n", startlba, endlba);

  ret = SBC_RawPrtReadBlock(blkhnd, (void *)imghdr, &imglen, startlba);
  if (ret != SBCOK) {
    eprint("SSBL Factory Block Read Fail \n");
    goto errdone;
  }
  //SBC_RET_VALIDATE_ERRCODEMSG((ret != SBCOK), SBCIO, "SSBL Factory Block Read Fail");


  CopyMem((void *)&imglen, &imghdr[0], sizeof imglen);
  // Temp code, at later, should be need to remove 
  //imglen = SBC_SWAP_ENDIAN_32(imglen);

  //dprint("SSBL Image Len : %d \n", imglen);
 
  imglen = ALIGN_VALUE(imglen, SBC_RAWPRT_DFLT_BLK_SZ);
  //dprint("Align Image Len : %d \n", imglen);
  //loadimg = AllocateZeroPool(imglen);
//if (loadimg == NULL) {
//  dprint("Allocate Image pool fail \n");
//  ret = SBCNULLP;
//  goto errdone;
//}

  dprint("Boot Service Allocate ");
  retval = gBS->AllocatePool(EfiBootServicesData, imglen, (VOID **)&loadimg);
  if (EFI_ERROR(retval)) {
    eprint("Faile to allocate memrory : %r", retval);
    ret = SBCNULLP;
    goto errdone;
  }

  ret = SBC_RawPrtReadBlock(blkhnd, (void *)loadimg, &imglen, startlba);
  if (ret != SBCOK) {
    eprint("SSBL Factory Block Read Fail \n");
    goto errdone;
  }

  if ((hndlcnt = SBC_FindEfiFileSystemProtocol(&ssbl_img_hndl)) <= 0) {
    dprint("File SYstem Handle Found fail \n");
    ret = SBCIO;
    goto errdone;
  }

  //dprint("File System Handle Found (Handle Count : %d) \n", hndlcnt);

  _lv_set_data(&wrlv,&loadimg[4], imglen - 4);

  //SBC_mem_print_bin("SSBL Load Image", wrlv.value, 512);
#if 1
  for (int idx = 0; idx < hndlcnt; idx++) {
    retval = SBC_WriteFile(ssbl_img_hndl[idx], fname, &wrlv);
    if (EFI_ERROR(retval)) {
        //eprint("%s file write fail %r", fname, retval);
        //dprint("%a file write fail %r \n", fname, retval);
        ret = SBCIO;
        continue;
        //goto errdone;
    }

    //dprint("Index %d Result : %d \n", idx, retval);
    break;
  }

  if (EFI_ERROR(retval)) {
    eprint("%s file write fail %r", fname, retval);
    ret = SBCIO;
    goto errdone;
  }



  dprint("SSBL Write is Done \n");
  //SBC_mem_print_bin("SSBL Header", imghdr, imglen);
  
  ret = SBC_SSBL_LoadAndStart(ImageHandle);
  if (ret != SBCOK) {
    dprint("SSBL Factory Running Fail \n");
    goto errdone;
  }
#else
extern SBCStatus  LoadAndStartMemoryImage(VOID *handle, VOID *imgbuf, UINTN imglen);

    ret = LoadAndStartMemoryImage(ImageHandle, wrlv.value, wrlv.length);

#endif
errdone:

  if (loadimg != NULL) {
    FreePool(loadimg);
  }



  return ret;

}



SBCStatus  SBC_BootModeNormal(UINT16 km, VOID *priv)
{
    SBCStatus ret = SBCOK;

    
    SBC_RET_VALIDATE_ERRCODEMSG((priv != NULL), SBCNULLP, "Invalid argument");

    switch (((boot_proc_t *)priv)->km) {
    case KEY_MODE_NORMAL:
      //VOID *hnd_load_img = NULL;
      sys_end_time = SBC_PerfNowTicks();
      //dprint("sys_end_time : %ld (%ld)", sys_end_time, sys_end_time - sys_start_time);
      sys_ns_var  = SBC_PerfTicksTons(_PerfDeltaTicks(sys_start_time, sys_end_time));
      //dprint("sys_ns_var : %ld", sys_ns_var);

      SBC_LogElapsedTime(L"SSBL Boot Time", sys_ns_var);      
      SBC_GRUB_LoadAndStart(((boot_proc_t *)priv)->ldhndl);
      while (TRUE) { }
      break;
    case KEY_MODE_BOOT:
      break;
    case KEY_MODE_UPDATE:
      break;
    default:
      eprint("Unknown Key Mode (%d)", km);
      goto errdone;
    }

errdone:
    return ret;

}


SBCStatus SBC_BootModeNormalAndpUdate(VOID *blkhnd, VOID *ImageHandle, VOID *priv)
{
  SBCStatus ret = SBCOK;


  switch (((boot_proc_t *)priv)->bm) {
  case BOOT_MODE_NORMAL:
    SBC_BootModeNormal(((boot_proc_t *)priv)->km, priv);
    break;
  case BOOT_MODE_UPDATE:
    break;
  case BOOT_MODE_RECOVERY:
    break;
  case BOOT_MODE_FACTORY:
    break;
  default:
    eprint("Unknown Boot Mode (%d)", ((boot_proc_t *)priv)->bm);
    goto errdone;
    break;
  }


errdone:
  return ret;

  
}

UINT32 FindPreviouslyBank(UINT32 bankid)
{
    UINT32 ret = 0;
    switch (bankid) {
    case 1:
        ret = 2;
        break;
    case 2:
        ret = 1;
        break;
    default:
        ret = 0x0;
        break;
    }

    return ret;
}

static BOOLEAN _get_fw_bankid(UINT32 val, UINT32 *cur, UINT32 *prev)
{
    UINT8 bank_first;
    UINT8 bank_second;

    bank_first  = (UINT8)((val >> 8) & 0xFF);
    bank_second = (UINT8)((val >> 24) & 0xFF);

    dprint("Banke First : %c , Bank Second : %c \n", bank_first, bank_second);

    if (bank_first == 'P' && bank_second == 'P') {
       return TRUE;
    }

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

extern SBCStatus SBC_GetOSIDFromRawPrt(VOID *priv, UINT8 *decbuf);
extern EFI_STATUS SBC_LogFileInit( EFI_HANDLE        logHandle);
SBCStatus SBC_RawPrtHdrChange(VOID *handle, UINT32 cur, UINT32 prev, UINT32 prevmode, UINT32 bm, UINT32 km);
EFI_STATUS
EFIAPI
UefiMain (
  IN EFI_HANDLE        ImageHandle,
  IN EFI_SYSTEM_TABLE  *SystemTable
  )
{



    atp_ident_t diceid;
    EFI_STATUS retval = EFI_SUCCESS;
    SBCStatus  ret = SBCOK;
    rawprt_hdr_t h_rawptrheader;    // Raw Partition Header handle
    //VOID *h_blkio;               // Block I/O handle
    [[maybe_unused]] UINT32 pres_hi = 0;
    UINT32 pres_low = 0;
    UINT32 currbank_id = 0;
    UINT32 prevbank_id = 0;
    //UINT32 bootmd = 0; // Boot Mode
    LV_t baseansr;

    
    [[gnu::unused]] CHAR8 bank_find;

    
    btproc.ldhndl = ImageHandle;
    btproc.b_forced = FALSE;


    SBC_LogFileInit(ImageHandle);

    sbc_err_sysprn(SBC_LOG_CMN_PRIO_INFO, 2,
                 SYS_LOG_HOST_BOOT,
                 SYS_LOG_APP_NAME,
                 SYS_LOG_CSC_NAME,
                 0,
                 SYS_LOG_EVT_DETECTION,
                 L"SBC_VENDOR_SP *** SSBL Statring ***");

    sys_start_time = SBC_PerfNowTicks();

    ZeroMem(&btproc, sizeof btproc);
    ZeroMem(&h_rawptrheader, sizeof h_rawptrheader);

    btproc.bootst = SB_PROC_ST_NRMA;
    // Get the NVMe SSD Raw Partiton handle and Header information
    ret = SBC_BlkIoHandleInit(&h_blkio, &h_rawptrheader);
    if (ret != SBCOK) {
          dprint("Raw Partitino find fail !!! \n");
          sbc_err_sysprn(SBC_LOG_CMN_PRIO_ERR, 2,
                     SYS_LOG_HOST_BOOT,
                     SYS_LOG_APP_NAME,
                     SYS_LOG_CSC_NAME,
                     0,
                     SYS_LOG_EVT_DETECTION,
                     L"SBC_SP_BlkIO Raw-Partition Not Detected");
          goto errdone;
    }

    SBC_mem_print_bin("Raw Prt Header", (UINT8 *)&h_rawptrheader, sizeof h_rawptrheader);


    
    //dprint("Find Raw Partition (0x%x)...\n", h_rawptrheader.magicid);
    dprint("Partition Info (%a) \n", h_rawptrheader.prtinfo);

    // Check the Preference SSBL bank
    CopyMem((void *)&pres_low, (void *)&h_rawptrheader.bootpres[0], 4);

    btproc.is_factory = _get_fw_bankid(pres_low, &currbank_id, &prevbank_id);
    dprint("Pres Low : 0x%04x Cur. Bank ID : %d , Prev. Bank ID : %d ", 
           pres_low, currbank_id, prevbank_id);
    //prevbank_id = FindPreviouslyBank(currbank_id);


    // Used from Recovery and Update 
    btproc.curr_sw_bnk = currbank_id;
    btproc.pvs_sw_bnk = prevbank_id;
//  if (prevbank_id < 1) {
//      eprint("Currently Valid FW Bank ID : %d , Previously Bank ID : %d \n", currbank_id, prevbank_id);
//      btproc.pvs_sw_bnk =
//      //retval = EFI_INVALID_PARAMETER;
//      //goto errdone;
//  }


    btproc.bm = h_rawptrheader.bootmode;
    btproc.km = h_rawptrheader.keymode;
    btproc.curr_sw_bnk = currbank_id;
    btproc.pvs_sw_bnk = prevbank_id;
    btproc.blkhnd = h_blkio;
    btproc.keyinfo = (VOID *)&diceid;
    btproc.rawprt_hdr = &h_rawptrheader;
    btproc.baseansr = (void *)&baseansr;
    // Added by Leo at 20251211
    btproc.prevmode = h_rawptrheader.prevmode;

    dprint("Prev. Mode is %d", btproc.prevmode);

    btproc.rcvmode = h_rawptrheader.rcvmode;

    dprint("Boot Mode : %d , Key Mode : %d, Recovery Mode : %d, Prev Mode : %d",
           btproc.bm, btproc.km, h_rawptrheader.rcvmode, h_rawptrheader.prevmode);

    //dprint("Chaeck Boot Mode read from BlkIO is %d", h_rawptrheader.bootmode);

#if 0   // Test for  read/write between Block 
    retval = SBC_CopyBlockReadAndBlockWrite( btproc.blkhnd,
                                             0x00000200,
                                             0x08400200,
                                             NULL);

    return EFI_SUCCESS;
#endif

#if 0
    extern SBCStatus _find_kernel_path(CHAR16 *fname);

    CHAR16 kernel_name[512] = {
        [0 ... 511] = 0
    };

    _find_kernel_path(kernel_name);

    SBC_mem_print_bin("Kernel Path", (UINT8 *)kernel_name, 64);
    dprint("kernel name : %s", kernel_name);






    return EFI_SUCCESS;
#endif
#if 0 //def _USECASE_TEST_

    {
        extern CHAR16 *sec_upt_name;
        extern UINTN boot_order_mode;
        extern SBCStatus UC_BootFWTamperingCheck(VOID *handle);
        extern SBCStatus UC_RecoveryAbnormalAndNormal(VOID *handle);
        EFI_STATUS retval = EFI_SUCCESS;
        SBCStatus ret = SBCOK;
        UINTN  varsz =  0;
        boot_proc_t *bp = &btproc;
        UINTN  set_order = 0;
        set_order = SBC_UC_MODE_UPDATE;
        varsz = sizeof set_order;
        //_ucprint("UINTN size :%d", sizeof set_order);
        SBC_NvramSetVar((VOID *)sec_upt_name, (VOID *)&set_order, (VOID *)&varsz);

        return EFI_SUCCESS;
        retval = SBC_NvramGetVar((VOID *)sec_upt_name, 
                                 (VOID *)&boot_order_mode,
                                 (VOID *)&varsz);

        if(EFI_ERROR(retval)) {
            if(retval == EFI_NOT_FOUND) {
                set_order = SBC_UC_MODE_UPDATE;
                varsz = sizeof set_order;
                //_ucprint("UINTN size :%d", sizeof set_order);
                SBC_NvramSetVar((VOID *)sec_upt_name, (VOID *)&set_order, (VOID *)&varsz);
            }
            //_ucprint("NVRAM get variable %d (%r)", varsz, retval);
        }

        switch (boot_order_mode) {
        case SBC_UC_MODE_UPDATE:
            sbc_err_sysprn(SBC_LOG_CMN_PRIO_INFO, 2,
                 SYS_LOG_HOST_BOOT,
                 SYS_LOG_APP_NAME,
                 SYS_LOG_CSC_NAME,
                 0,
                 L"Information",
                 L"Update Mode Testing");
            ret = UC_BootFWTamperingCheck(bp);
            if (ret != SBCOK) {
                goto uc_errdone;
            }
            break;
        case SBC_UC_MODE_RECOVERY:
            sbc_err_sysprn(SBC_LOG_CMN_PRIO_INFO, 2,
                 SYS_LOG_HOST_BOOT,
                 SYS_LOG_APP_NAME,
                 SYS_LOG_CSC_NAME,
                 0,
                 L"Information",
                 L"Recovery Mode Testing");
            ret = UC_RecoveryAbnormalAndNormal(bp);

            set_order = SBC_UC_MODE_UPDATE;
            varsz = sizeof set_order;
            //_ucprint("UINTN size :%d", sizeof set_order);
            SBC_NvramSetVar((VOID *)sec_upt_name, (VOID *)&set_order, (VOID *)&varsz);
            SBC_RebootSystem();
            break;

        default:
            set_order = SBC_UC_MODE_UPDATE;
            varsz = sizeof set_order;
            //_ucprint("UINTN size :%d", sizeof set_order);
            SBC_NvramSetVar((VOID *)sec_upt_name, (VOID *)&set_order, (VOID *)&varsz);
            SBC_RebootSystem();
            break;
                
        }
uc_errdone:
        return retval;
    }
#endif

#if 0
    ret = SBC_GenMigrationKey((void *)&btproc, diceid.migid);
    SBC_external_mem_print_bin("Migration Key", diceid.migid, 32);

    {
        UINTN   line  = 0ULL;
        UINTN   cnt;

        UINT8  deckey[32];
        UINT8  enckey[32];

        ret = SBC_DiceKeysGen(ImageHandle, &diceid,  currbank_id, btproc.bm);
        if (ret != SBCOK) {
            sbc_err_sysprn(SBC_LOG_CMN_PRIO_ERR, 2,
                 SYS_LOG_HOST_BOOT,
                 SYS_LOG_APP_NAME,
                 SYS_LOG_CSC_NAME,
                 1,
                 SYS_LOG_EVT_VALDIATION,
                 L"HW&SW Base Key Creation Fail");
            retval = EFI_INVALID_PARAMETER;
            btproc.bootst = SB_PROC_ST_ABNRAM;
            goto errdone;
        }

        SBC_GenMigrationKey((void *)&btproc, diceid.migid);

        SBC_ProtSWGetCnt((VOID *)&btproc, &line);

        dprint("Protected Software Count : %ld", line);

        for (cnt = 0; cnt < line; cnt++ ) {
            CHAR8 sw_name[256] = {0, };
            UINTN sw_name_len = 0ULL;

            SBC_GetProtectedSwName((void *)&btproc, cnt, sw_name, 256);
            //sw_name[sw_name_len] = '\0';
            dprint("SW Name : %a, Name Len : %ld", sw_name, sw_name_len);

        }

        SBC_HashCompute(NULL, ((atp_ident_t *)btproc.keyinfo)->migid, 32, deckey);
        SBC_HashCompute(NULL, ((atp_ident_t *)btproc.keyinfo)->osid, 32, enckey);


        SBC_ProtSWDecrypt((VOID *)&btproc,
                          enckey,
                          deckey,
                          NULL,
                          NULL);
        return EFI_SUCCESS;
    }
#endif 

#if 0
    SBC_BootKeyModeChange(BOOT_MODE_UPDATE, KEY_MODE_NORMAL, (void *)&btproc);
    goto errdone;
#endif
    dprint("Currently Valid FW Bank ID : %d , Previously Bank ID : %d \n", currbank_id, prevbank_id);


//  {
//      UINT8 old_osid[32] = {0, };
//      ret = SBC_GetOSIDFromRawPrt((VOID *)&btproc, old_osid);
//      if (ret != SBCOK) {
//          eprint("Get Old OSID getting fail");
//          dprint("xxxxxxxxxxxxxxxxx22222xxxxxxxxxxxx");
//          goto errdone;
//      }
//      else {
//          dprint("xxxxxxxxxxxxxxxxxxxxxxxxxxxxx");
//          dprint("Get Old osid getting success");
//      }
//      SBC_mem_print_bin("OLD OSID", old_osid, sizeof old_osid);
//      return EFI_SUCCESS;
//  }
//  {
//      extern SBCStatus  SBC_DiceKeysGenOld(EFI_HANDLE ImageHandle,
//                                           VOID *p,
//                                           UINTN normbank,
//                                           UINTN bm);
//      atp_ident_t key1;
//      atp_ident_t key2;
//      UINT64 wrbytes;
//      UINT32 rdbytes =0;
//
//      SBC_CopyFileToBlockDevice(L"\\EFI\\BOOT\\SSBL.efi",
//                                btproc.blkhnd,
//                                0x400200,
//                                &wrbytes);
//
//      dprint("SSBL write byte at 0x400200 %lu", wrbytes);
//
//      ret = SBC_RawPrtHdrChange((void *)&btproc,
//                                    1,
//                                    2,
//                                    0,
//                                    BOOT_MODE_UNKNOWN,
//                                    KEY_MODE_UNKNOWN);
//      btproc.curr_sw_bnk = 1;
//      btproc.pvs_sw_bnk = 2;
//      SBC_DiceKeysGenOld(ImageHandle, &key1, btproc.curr_sw_bnk, btproc.bm);
//
//      SBC_mem_print_bin("Curr OSID", (UINT8 *)key1.osid, 32);
//
//      SBC_CopyBlockReadAndBlockWrite(btproc.blkhnd,
//                                     0x400200,
//                                     0x8400200,
//                                     &rdbytes);
//
//      ret = SBC_RawPrtHdrChange((void *)&btproc,
//                                    2,
//                                    1,
//                                    0,
//                                    BOOT_MODE_UNKNOWN,
//                                    KEY_MODE_UNKNOWN);
//
//      btproc.curr_sw_bnk = 2;
//       btproc.pvs_sw_bnk = 1;
//      SBC_DiceKeysGenOld(ImageHandle, &key2, btproc.curr_sw_bnk, btproc.bm);
//
//      SBC_mem_print_bin("Prev OSID", (UINT8 *)key2.osid, 32);
//        return EFI_SUCCESS;
//
//      SBC_CopyBlockReadAndBlockWrite(btproc.blkhnd,
//                                     0x8400200,
//                                     0x400200,
//                                     &rdbytes);
//    }

#if 0
    ret = SBC_GenMigrationKey((void *)&btproc, diceid.migid);
    if (ret != SBCOK) {
      sbc_err_sysprn(SBC_LOG_CMN_PRIO_ERR, 2, SYS_LOG_HOST_BOOT, SYS_LOG_APP_NAME,SYS_LOG_CSC_NAME, 4, SYS_LOG_EVT_DETECTION, L"Migration Key creation fail\n");
      retval = EFI_INVALID_PARAMETER;
      btproc.bootst = SB_PROC_ST_ABNRAM;
      goto errdone;
    }

    SBC_external_mem_print_bin("Migraiotn Key", diceid.migid, 32);
    return EFI_SUCCESS;
#endif

#ifdef _USECASE_TEST_
    _ucprint("*** SSBL Boot FW Self-validation \n");
#endif



    ret = SBC_SSBL_Verify(h_blkio, &baseansr, btproc.curr_sw_bnk, btproc.bm );
    if (ret != SBCOK) {
          sbc_err_sysprn(SBC_LOG_CMN_PRIO_ERR, 2,
                 SYS_LOG_HOST_BOOT,
                 SYS_LOG_APP_NAME,
                 SYS_LOG_CSC_NAME,
                 5,
                 SYS_LOG_EVT_DETECTION,
                 L"SBC_tamper_SSBL signature verification faied\n");
          retval = EFI_INVALID_PARAMETER;
          btproc.bootst = SB_PROC_ST_ABNRAM;
          btproc.b_forced = TRUE;
          goto errdone;
    }

#ifdef _KERNEL_VERIFY_
    ret = SBC_Kernel_Verify((void *)&btproc);
    if (ret != SBCOK) {
          sbc_err_sysprn(SBC_LOG_CMN_PRIO_ERR, 2,
                 SYS_LOG_HOST_BOOT,
                 SYS_LOG_APP_NAME,
                 SYS_LOG_CSC_NAME,
                 5,
                 SYS_LOG_EVT_DETECTION,
                 L"SBC_tamper_OS image signature verification faied\n");
          retval = EFI_INVALID_PARAMETER;
          btproc.bootst = SB_PROC_ST_ABNRAM;
          btproc.b_forced = TRUE;
          goto errdone;
    }
    //return EFI_SUCCESS;
#endif

    ret = SBC_DiceKeysGen(ImageHandle, &diceid,  currbank_id, btproc.bm);
    if (ret != SBCOK) {
        sbc_err_sysprn(SBC_LOG_CMN_PRIO_ERR, 2,
             SYS_LOG_HOST_BOOT,
             SYS_LOG_APP_NAME,
             SYS_LOG_CSC_NAME,
             1,
             SYS_LOG_EVT_VALDIATION,
             L"SBC_Dice_Key HW&SW Base Key Creation Fail");
        retval = EFI_INVALID_PARAMETER;
        btproc.bootst = SB_PROC_ST_ABNRAM;
        goto errdone;
    }

    btproc.diceid = (VOID *)&diceid;

//  sbc_err_sysprn(SBC_LOG_CMN_PRIO_INFO, 2,
//       SYS_LOG_HOST_BOOT,
//       SYS_LOG_APP_NAME,
//       SYS_LOG_CSC_NAME,
//       1,
//       SYS_LOG_EVT_VALDIATION,
//       L"SBC_Dice_Key HW&SW Base Key Creation Success");

    if (h_rawptrheader.bootmode != BOOT_MODE_NORMAL) {
        
        sbc_err_sysprn(SBC_LOG_CMN_PRIO_INFO, 2,
             SYS_LOG_HOST_BOOT,
             SYS_LOG_APP_NAME,
             SYS_LOG_CSC_NAME,
             8,
             SYS_LOG_EVT_VALDIATION,
             L"SBC_Integrity_All boot components passed signature verification \n");
    }
#if defined(_FILE_RD_BM_)
//#warning   "SBC Boot Mode Read from File"
    UINT32 bootmd = SBC_ReadBootMode();
    dprint("Boot Mode read from File %d" , bootmd);
    if (h_rawptrheader.bootmode != 0) {
        bootmd = h_rawptrheader.bootmode;
    }
    switch (bootmd) {
#else
    dprint("Boot Mode read from BlkIO is %d", h_rawptrheader.bootmode);
    switch (h_rawptrheader.bootmode) {
#endif
    case BOOT_MODE_NORMAL:
#if defined(_FILE_RD_BM_)
        h_rawptrheader.keymode = KEY_MODE_NORMAL;
        SBC_BootKeyModeChange(BOOT_MODE_NORMAL, KEY_MODE_NORMAL, (void *)&btproc);
#endif
       dprint("Boot Mode is BOOT_MODE_NORMAL");

       if (h_rawptrheader.rcvmode) {
            sbc_err_sysprn(SBC_LOG_CMN_PRIO_INFO, 
                             2, 
                             SYS_LOG_HOST_BOOT, 
                             SYS_LOG_APP_NAME,SYS_LOG_CSC_NAME, 
                             0, 
                             SYS_LOG_EVT_DETECTION, 
                             L"SBC_BootFW The System has booted from recovery mode \n");

            ret = SBC_GenMigrationKey((void *)&btproc, diceid.migid);
            if (ret != SBCOK) {
                sbc_err_sysprn(SBC_LOG_CMN_PRIO_ERR, 
                             2, 
                             SYS_LOG_HOST_BOOT, 
                             SYS_LOG_APP_NAME,SYS_LOG_CSC_NAME, 
                             4, 
                             SYS_LOG_EVT_DETECTION, 
                             L"SBC_BootFW_Update Fail to MigrationKey Creation \n");
                retval = EFI_INVALID_PARAMETER;
                btproc.bootst = SB_PROC_ST_ABNRAM;

              // 
              // No need to return because change the boot mode and reset the system.
              //
            }

            if (ret == SBCOK) {
                SBC_BuildHexFormattedMessage(
                    (CONST VOID *)diceid.migid, 32,
                    L"SBC_BootFW_Update Migration Key  (%s)\n",
                    mrgmsg, sizeof mrgmsg);

                sbc_err_sysprn(SBC_LOG_CMN_PRIO_INFO, 2,
                     SYS_LOG_HOST_BOOT,
                     SYS_LOG_APP_NAME,
                     SYS_LOG_CSC_NAME,
                     1,
                     SYS_LOG_EVT_DETECTION,
                     mrgmsg);
            }
       }

       ret = SBC_SecureBootCheck((VOID *)&btproc);

       break;
    case BOOT_MODE_FACTORY:
       dprint("Boot Mode is BOOT_MODE_FACTORY");





       // If boot status is abnromal, system should be shutdown.
//     if (btproc.bootst != SB_PROC_ST_NRMA) {
//         eprint("Factory Boot Mode is Abnormal, so, it goes to shutdown state");
//         ret = SBCFAIL;
//         goto errdone;
//     }

       ret = SBC_SecureBootCheck((VOID *)&btproc);
       if (ret != SBCOK) {
           eprint("Secure Boot check fail for BOOT_MODE_FACTORY");
           goto errdone;
       }
        sys_end_time = SBC_PerfNowTicks();
        //dprint("sys_end_time : %ld (%ld)", sys_end_time, sys_end_time - sys_start_time);
        sys_ns_var  = SBC_PerfTicksTons(_PerfDeltaTicks(sys_start_time, sys_end_time));
        //dprint("sys_ns_var : %ld", sys_ns_var);

        SBC_LogElapsedTime(L"SSBL Factoory Boot Time", sys_ns_var); 

        sbc_err_sysprn(SBC_LOG_CMN_PRIO_NOTICE, 2, 
            SYS_LOG_HOST_BOOT, 
            SYS_LOG_APP_NAME, 
            SYS_LOG_CSC_NAME, 
            8, 
            L"Validation ", 
            L"SBC_VENDOR_SP Grub Load Done");  

        ret = SBC_GRUB_LoadAndStart(ImageHandle);
        if(ret != SBCOK) {
            sbc_err_sysprn(SBC_LOG_CMN_PRIO_ERR, 2, 
                    SYS_LOG_HOST_BOOT, 
                    SYS_LOG_APP_NAME, 
                   SYS_LOG_CSC_NAME, 
                    8, 
                    L"Detection ", 
                    L"SBC_VENDOR_SP Grub Load fail");
            retval = EFI_INVALID_PARAMETER;
        }

        sbc_err_sysprn(SBC_LOG_CMN_PRIO_NOTICE, 2, 
            SYS_LOG_HOST_BOOT, 
            SYS_LOG_APP_NAME, 
            SYS_LOG_CSC_NAME, 
            8, 
            L"Validation ", 
            L"SBC_VENDOR_SP Grub Load Done");      
       //dprint("Factory Boot Mode !!! \n");
       //ret = SBCFAIL;
       //goto errdone;
       break;
    case BOOT_MODE_UPDATE:
        dprint("Boot Mode BOOT_MODE_UPDATE");
#ifdef _FILE_RD_BM_
        btproc.bm = BOOT_MODE_UPDATE;
        btproc.km = KEY_MODE_NORMAL;
#endif
      ret = SBC_GenMigrationKey((void *)&btproc, diceid.migid);
      if (ret != SBCOK) {
          sbc_err_sysprn(SBC_LOG_CMN_PRIO_ERR, 
                         2, 
                         SYS_LOG_HOST_BOOT, 
                         SYS_LOG_APP_NAME,SYS_LOG_CSC_NAME, 
                         4, 
                         SYS_LOG_EVT_DETECTION, 
                         L"SBC_BootFW_Update Fail to MigrationKey Creation \n");
          retval = EFI_INVALID_PARAMETER;
          btproc.bootst = SB_PROC_ST_ABNRAM;

          // 
          // No need to return because change the boot mode and reset the system.
          //
      }

      if (ret == SBCOK) {
          SBC_BuildHexFormattedMessage(
                (CONST VOID *)diceid.migid, 32,
                L"SBC_BootFW_Update Migration Key  (%s)\n",
                mrgmsg, sizeof mrgmsg);

          sbc_err_sysprn(SBC_LOG_CMN_PRIO_INFO, 2,
                 SYS_LOG_HOST_BOOT,
                 SYS_LOG_APP_NAME,
                 SYS_LOG_CSC_NAME,
                 1,
                 SYS_LOG_EVT_DETECTION,
                 mrgmsg);
      }

      ret = SBC_SecureBootCheck((VOID *)&btproc);
      if (ret != SBCOK) {
          eprint("Secure Boot check fail for BOOT_MODE_UPDATE");
          goto errdone;
      }
      dprint("Boot Mode is BOOT_MODE_UPDATE");
      break;
    case BOOT_MODE_RECOVERY:
        dprint("Boot Mode BOOT_MODE_RECOVERY");

        ret = SBC_GenMigrationKey((void *)&btproc, diceid.migid);
        if (ret != SBCOK) {
            sbc_err_sysprn(SBC_LOG_CMN_PRIO_ERR, 
                         2, 
                         SYS_LOG_HOST_BOOT, 
                         SYS_LOG_APP_NAME,SYS_LOG_CSC_NAME, 
                         4, 
                         SYS_LOG_EVT_DETECTION, 
                         L"SBC_BootFW_Update Fail to MigrationKey Creation \n");
            retval = EFI_INVALID_PARAMETER;
            btproc.bootst = SB_PROC_ST_ABNRAM;

          // 
          // No need to return because change the boot mode and reset the system.
          //
        }

        if (ret == SBCOK) {
            SBC_BuildHexFormattedMessage(
                (CONST VOID *)diceid.migid, 32,
                L"SBC_BootFW_Recovery Migration Key  (%s)\n",
                mrgmsg, sizeof mrgmsg);

            sbc_err_sysprn(SBC_LOG_CMN_PRIO_INFO, 2,
                 SYS_LOG_HOST_BOOT,
                 SYS_LOG_APP_NAME,
                 SYS_LOG_CSC_NAME,
                 1,
                 SYS_LOG_EVT_DETECTION,
                 mrgmsg);

            btproc.bootst = SB_PROC_ST_NRMA;
        }
        ret = SBC_SecureBootCheck((VOID *)&btproc);
        break;
    default:
      dprint("Unknown Boot Mode ... SHOULD go to Abort\n");
      break;
    }

    if (ret != SBCOK) {
        goto errdone;
    }

    sys_end_time = SBC_PerfNowTicks();
    //dprint("sys_end_time : %ld (%ld)", sys_end_time, sys_end_time - sys_start_time);
    sys_ns_var  = SBC_PerfTicksTons(_PerfDeltaTicks(sys_start_time, sys_end_time));
    //dprint("sys_ns_var : %ld", sys_ns_var);

    SBC_LogElapsedTime(L"SSBL Boot Time", sys_ns_var); 
    ret = SBC_GRUB_LoadAndStart(ImageHandle);
    if(ret != SBCOK) {
        sbc_err_sysprn(SBC_LOG_CMN_PRIO_ERR, 2, 
                SYS_LOG_HOST_BOOT, 
                SYS_LOG_APP_NAME, 
               SYS_LOG_CSC_NAME, 
                8, 
                L"Detection ", 
                L"SBC_VENDOR_SP Grub Load fail");
        retval = EFI_INVALID_PARAMETER;
    }

    sbc_err_sysprn(SBC_LOG_CMN_PRIO_NOTICE, 2, 
        SYS_LOG_HOST_BOOT, 
        SYS_LOG_APP_NAME, 
        SYS_LOG_CSC_NAME, 
        8, 
        L"Validation ", 
        L"SBC_VENDOR_SP Grub Load Done");

    //ret = SBC_FSBL_Verify(h_blkio, &baseansr);

  // Read SSBL from



  // Access bank addr ( (0x200 + (128 << 20)) * currbank_id )


errdone:
#ifdef _ALL_PASS_
    SBC_GRUB_LoadAndStart(ImageHandle);
    return retval;
#endif
    if (ret != SBCOK) {
        //
        // Not existense the shutd-down scenario
        //
#ifdef _FORCED_SHUTDOWN_
        if (btproc.b_forced == TRUE) {
            SBC_ShutdownSystem();
        }
#endif
        ret = SBC_SecureBootCheck((VOID *)&btproc);

        //SBC_ShutdownSystem();
    }

    dprint("Genereally return from SSBL with Boot Mode %u and Key Mode %u",
           btproc.bm,  btproc.km );

    return retval;
}

// Shell Reboot but do not jump to Grub 
//EFI_BOOT_MANAGER_LOAD_OPTION *BootOptions;
//UINTN BootOptionCount;
//
//
//dprint("Start BOOt .. !! \n");
//BootOptions = NULL;
//BootOptionCount = 0;
//
//BootOptions = EfiBootManagerGetLoadOptions(&BootOptionCount, LoadOptionTypeBoot);
//
//EfiBootManagerBoot(BootOptions);
