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



SBCStatus  SBC_DiceKeysGen(EFI_HANDLE ImageHandle, VOID *p)
{
    SBCStatus ret = SBCOK;
    atp_ident_t *h = NULL;

    h = (atp_ident_t *)p;

    ret = SBC_GenDeviceID(h->devid);
    if (ret != SBCOK) {
        Print(L"Device ID generate fail \n");
        goto errdone;
    }

    //SBC_mem_print_bin("Device ID", h->devid, sizeof h->devid);SBC_mem_print_bin("Device ID", h->devid, sizeof h->devid);

    ret = SBC_GenFWID(ImageHandle, h->devid, h->fwid);
    if (ret != SBCOK) {
        Print(L"FW ID generate fail \n");
        goto errdone;
    }

    //SBC_mem_print_bin("Firmware ID", h->fwid, sizeof h->fwid);

    ret = SBC_GenOSID(ImageHandle,  h->fwid, h->osid);
    if (ret != SBCOK) {
        Print(L"FW ID generate fail \n");
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
  [[gnu::unused]]CHAR16 *fname = L"\\EFI\\rocky\\SSBL.efi";


  LV_t wrlv;
  //UINT8 *imgssbl = NULL;

  SBC_RET_VALIDATE_ERRCODEMSG((blkhnd != NULL), SBCNULLP, "Block I/O Handle Nill");

  startlba = ((BOOT_SECTOR3_OFS | BOOT_SSBL_OFS) >> SBC_RAWPRT_DFLT_SHIFT);
  //Print("Start LBA Address : 0x%x  \n")
  //endlba = (BOOT_SSBL_MAX >>  SBC_RAWPRT_DFLT_SHIFT) - startlba;

  //Print(L"Start Addr : 0x%lx , End addr : 0x%lx \n", startlba, endlba);

  ret = SBC_RawPrtReadBlock(blkhnd, (void *)imghdr, &imglen, startlba);
  if (ret != SBCOK) {
    Print(L"SSBL Factory Block Read Fail \n");
    goto errdone;
  }
  //SBC_RET_VALIDATE_ERRCODEMSG((ret != SBCOK), SBCIO, "SSBL Factory Block Read Fail");


  CopyMem((void *)&imglen, &imghdr[0], sizeof imglen);
  // Temp code, at later, should be need to remove 
  //imglen = SBC_SWAP_ENDIAN_32(imglen);

  //Print(L"SSBL Image Len : %d \n", imglen);
 
  imglen = ALIGN_VALUE(imglen, SBC_RAWPRT_DFLT_BLK_SZ);
  //Print(L"Align Image Len : %d \n", imglen);
  //loadimg = AllocateZeroPool(imglen);
//if (loadimg == NULL) {
//  Print(L"Allocate Image pool fail \n");
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
    Print(L"SSBL Factory Block Read Fail \n");
    goto errdone;
  }

  if ((hndlcnt = SBC_FindEfiFileSystemProtocol(&ssbl_img_hndl)) <= 0) {
    Print(L"File SYstem Handle Found fail \n");
    ret = SBCIO;
    goto errdone;
  }

  //Print(L"File System Handle Found (Handle Count : %d) \n", hndlcnt);

  _lv_set_data(&wrlv,&loadimg[4], imglen - 4);

  //SBC_mem_print_bin("SSBL Load Image", wrlv.value, 512);
#if 1
  for (int idx = 0; idx < hndlcnt; idx++) {
    retval = SBC_WriteFile(ssbl_img_hndl[idx], fname, &wrlv);
    if (EFI_ERROR(retval)) {
        //eprint("%s file write fail %r", fname, retval);
        //Print(L"%a file write fail %r \n", fname, retval);
        ret = SBCIO;
        continue;
        //goto errdone;
    }

    //Print(L"Index %d Result : %d \n", idx, retval);
    break;
  }

  if (EFI_ERROR(retval)) {
    eprint("%s file write fail %r", fname, retval);
    ret = SBCIO;
    goto errdone;
  }



  Print(L"SSBL Write is Done \n");
  //SBC_mem_print_bin("SSBL Header", imghdr, imglen);
  
  ret = SBC_SSBL_LoadAndStart(ImageHandle);
  if (ret != SBCOK) {
    Print(L"SSBL Factory Running Fail \n");
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


SBCStatus SBC_BootModeNormalAndpUdate(VOID *blkhnd, VOID *ImageHandle, UINTN nrombank)
{
  SBCStatus ret = SBCOK;
  
  UINTN startlba = 0;
  

  UINT32  imglen = SBC_RAWPRT_DFLT_BLK_SZ;
  UINT8   imghdr[SBC_RAWPRT_DFLT_BLK_SZ] = {0, };
  UINT8   *loadimg = NULL;
  UINTN   bsofs = 0; // Boot Sector Offset
  

  EFI_HANDLE  *ssbl_img_hndl;
  [[maybe_unused]]UINTN endlba = 0;
  [[maybe_unused]]INTN       hndlcnt = 0;
  __attribute__((unused))EFI_STATUS retval;
  [[gnu::unused]]CHAR16 *fname = L"\\EFI\\rocky\\SSBL.efi";


  LV_t wrlv;
  //UINT8 *imgssbl = NULL;

  dprint("----- Normal Boot SSBL running ( Bank Id : 0x%x ) -----", nrombank);

  SBC_RET_VALIDATE_ERRCODEMSG((nrombank > 0 && nrombank < 3), SBCINVPARAM, "Invalid Parameter for SSBL bank");
  SBC_RET_VALIDATE_ERRCODEMSG((blkhnd != NULL), SBCNULLP, "Block I/O Handle Nill");

  bsofs = (BOOT_SECTOR1_OFS | ((nrombank - 1) << 20));
  startlba = ((bsofs | BOOT_SSBL_OFS) >> SBC_RAWPRT_DFLT_SHIFT);

  //Print("Start LBA Address : 0x%x  \n")
  //endlba = (BOOT_SSBL_MAX >>  SBC_RAWPRT_DFLT_SHIFT) - startlba;

  //Print(L"Start Addr : 0x%lx , End addr : 0x%lx \n", startlba, endlba);

  ret = SBC_RawPrtReadBlock(blkhnd, (void *)imghdr, &imglen, startlba);
  if (ret != SBCOK) {
    Print(L"SSBL Factory Block Read Fail \n");
    goto errdone;
  }
  //SBC_RET_VALIDATE_ERRCODEMSG((ret != SBCOK), SBCIO, "SSBL Factory Block Read Fail");


  CopyMem((void *)&imglen, &imghdr[0], sizeof imglen);
  // Temp code, at later, should be need to remove 
  //imglen = SBC_SWAP_ENDIAN_32(imglen);

  //Print(L"SSBL Image Len : %d \n", imglen);
 
  imglen = ALIGN_VALUE(imglen, SBC_RAWPRT_DFLT_BLK_SZ);
  //Print(L"Align Image Len : %d \n", imglen);
  //loadimg = AllocateZeroPool(imglen);
//if (loadimg == NULL) {
//  Print(L"Allocate Image pool fail \n");
//  ret = SBCNULLP;
//  goto errdone;
//}

  //dprint("Boot Service Allocate ");
  retval = gBS->AllocatePool(EfiBootServicesData, imglen, (VOID **)&loadimg);
  if (EFI_ERROR(retval)) {
    eprint("Faile to allocate memrory : %r", retval);
    ret = SBCNULLP;
    goto errdone;
  }

  ret = SBC_RawPrtReadBlock(blkhnd, (void *)loadimg, &imglen, startlba);
  if (ret != SBCOK) {
    Print(L"SSBL Factory Block Read Fail \n");
    goto errdone;
  }

  if ((hndlcnt = SBC_FindEfiFileSystemProtocol(&ssbl_img_hndl)) <= 0) {
    Print(L"File SYstem Handle Found fail \n");
    ret = SBCIO;
    goto errdone;
  }

  //Print(L"File System Handle Found (Handle Count : %d) \n", hndlcnt);

  _lv_set_data(&wrlv,&loadimg[4], imglen - 4);

  //SBC_mem_print_bin("SSBL Load Image", wrlv.value, 512);
#if 1
  for (int idx = 0; idx < hndlcnt; idx++) {
    retval = SBC_WriteFile(ssbl_img_hndl[idx], fname, &wrlv);
    if (EFI_ERROR(retval)) {
        //eprint("%s file write fail %r", fname, retval);
        //Print(L"%a file write fail %r \n", fname, retval);
        ret = SBCIO;
        continue;
        //goto errdone;
    }

    //Print(L"Index %d Result : %d \n", idx, retval);
    break;
  }

  if (EFI_ERROR(retval)) {
    eprint("%s file write fail %r", fname, retval);
    ret = SBCIO;
    goto errdone;
  }



  Print(L"SSBL Write is Done \n");
  //SBC_mem_print_bin("SSBL Header", imghdr, imglen);
  
  ret = SBC_SSBL_LoadAndStart(ImageHandle);
  if (ret != SBCOK) {
    Print(L"SSBL Factory Running Fail \n");
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
        ret = 0xFFFFFFFF;
        break;
    }

    return ret;
}



EFI_STATUS
EFIAPI
UefiMain (
  IN EFI_HANDLE        ImageHandle,
  IN EFI_SYSTEM_TABLE  *SystemTable
  )
{

extern SBCStatus SBC_GRUB_LoadAndStart(EFI_HANDLE ImageHandle);


    atp_ident_t diceid;
    EFI_STATUS retval = EFI_SUCCESS;
    SBCStatus  ret = SBCOK;
    rawprt_hdr_t h_rawptrheader;    // Raw Partition Header handle
    VOID *h_blkio;               // Block I/O handle
    UINT32 pres_hi = 0;
    UINT32 pres_low = 0;
    UINT32 currbank_id = 0;
    UINT32 prevbank_id = 0;
    UINT32 bootmd = 0; // Boot Mode
    LV_t baseansr;
 

    intgreen_dprint("------------- SSBL Factory System START -------------\n");

    ZeroMem(&h_rawptrheader, sizeof h_rawptrheader);
    // Get the NVMe SSD Raw Partiton handle and Header information
    ret = SBC_BlkIoHandleInit(&h_blkio, &h_rawptrheader);
    if (ret != SBCOK) {
      Print(L"Raw Partitino find fail !!! \n");
      ASSERT((ret != SBCOK));
    }

    //Print(L"Find Raw Partition (0x%x)...\n", h_rawptrheader.magicid);
    dprint("Partition Info (%a) \n", h_rawptrheader.prtinfo);

    // Check the Preference SSBL bank
    CopyMem((void *)&pres_low, (void *)&h_rawptrheader.bootpres[0], 4);
    CopyMem((void *)&pres_hi, (void *)&h_rawptrheader.bootpres[4], 4);

    pres_low = SBC_SWAP_ENDIAN_32(pres_low);
    pres_hi = SBC_SWAP_ENDIAN_32(pres_hi);

    //sbc_err_sysprn(SBC_LOG_CMN_PRIO_INFO, 2, L"SBC", L"FSBL", L"xxx", 233, L"EVT", L"Pres HI : 0x%x , Pres Low: %a \n", "holla oops");
    Print(L"Pres HI : 0x%x , Pres Low: 0x%x \n", pres_low, pres_hi);

    //SBC_mem_print_bin("Pres Low", (UINT8 *)&pres_low, 4);
    //SBC_mem_print_bin("Pres Hi", (UINT8 *)&pres_hi, 4);

    if ((CHAR8)(pres_low & 0x0000FFFF) == 'C') {
      currbank_id = (pres_low & 0xFFFF0000) >> 16;
    }
    else if ((CHAR8)(pres_hi & 0x0000FFFF) == 'C') {
      currbank_id = (pres_hi & 0xFFFF0000) >> 16;
    }

    prevbank_id = FindPreviouslyBank(currbank_id);
    if (prevbank_id < 1) {
        eprint("Currently Valid FW Bank ID : %d , Previously Bank ID : %d \n", currbank_id, prevbank_id);
        retval = EFI_INVALID_PARAMETER;
        goto errdone;
    }
    dprint("Currently Valid FW Bank ID : %d , Previously Bank ID : %d \n", currbank_id, prevbank_id);

    ret = SBC_SSBL_Verify(h_blkio, &baseansr, currbank_id);
    if (ret != SBCOK) {
          sbc_err_sysprn(SBC_LOG_CMN_PRIO_ERR, 2, 
                 L"SBC", 
                 L"FSBL", 
                 L"Weapon System", 
                 8, 
                 L"Determine Firmare Tampering ", 
                 L"FSBL tampering check fail");
          retval = EFI_INVALID_PARAMETER;
          goto errdone;
      }




    ret = SBC_DiceKeysGen(ImageHandle, &diceid);
    if (ret != SBCOK) {
        sbc_err_sysprn(SBC_LOG_CMN_PRIO_ERR, 2, L"SBC", L"FSBL", L"Weapon System", 4, L"EVT", L"Dice Key creation fail\n");
        retval = EFI_INVALID_PARAMETER;
        goto errdone;
    }

    ret = SBC_GenMigrationKey(h_blkio, currbank_id, prevbank_id, diceid.migid);
    if (ret != SBCOK) {
        sbc_err_sysprn(SBC_LOG_CMN_PRIO_ERR, 2, L"SBC", L"FSBL", L"Weapon System", 4, L"EVT", L"Migration Key creation fail\n");
        retval = EFI_INVALID_PARAMETER;
        goto errdone;
    }

    SBC_external_mem_print_bin("Migraiotn Key", diceid.migid, 32);

    sbc_err_sysprn(SBC_LOG_CMN_PRIO_INFO, 2, L"SBC", L"FSBL", L"Weapon System", 4, L"EVT", L"Migration Key creation Success\n");

    
           
    // Check boot mode
    bootmd = SBC_ReadBootMode();
    switch (bootmd) {
    case BOOT_MODE_NORMAL:
       dprint("Boot Mode is BOOT_MODE_NORMAL");
       break;
    case BOOT_MODE_FACTORY:
       dprint("Boot Mode is BOOT_MODE_FACTORY");
      //Print(L"Factory Boot Mode !!! \n");
      break;
    case BOOT_MODE_UPDATE:
       dprint("Boot Mode is BOOT_MODE_UPDATE");
      break;
    default:
      Print(L"Unknown Boot Mode ... SHOULD go to Abort\n");
      break;
    }

    ret = SBC_GRUB_LoadAndStart(ImageHandle);
    if(ret != SBCOK) {
        sbc_err_sysprn(SBC_LOG_CMN_PRIO_ERR, 2, 
                L"SBC", 
                L"FSBL", 
                L"Weapon System", 
                8, 
                L"Determine Firmare Tampering ", 
                L"FSBL tampering check fail");
        retval = EFI_INVALID_PARAMETER;
    }

    //ret = SBC_FSBL_Verify(h_blkio, &baseansr);

  // Read SSBL from



  // Access bank addr ( (0x200 + (128 << 20)) * currbank_id )


errdone:
 
   return retval;
}

// Shell Reboot but do not jump to Grub 
//EFI_BOOT_MANAGER_LOAD_OPTION *BootOptions;
//UINTN BootOptionCount;
//
//
//Print(L"Start BOOt .. !! \n");
//BootOptions = NULL;
//BootOptionCount = 0;
//
//BootOptions = EfiBootManagerGetLoadOptions(&BootOptionCount, LoadOptionTypeBoot);
//
//EfiBootManagerBoot(BootOptions);
