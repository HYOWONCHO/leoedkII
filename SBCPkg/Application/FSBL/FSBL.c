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
    //SBC_mem_print_bin("Device ID", h->devid, sizeof h->devid);
    ret = SBC_GenFWID(ImageHandle, h->devid, h->fwid, normbank, bm);
    if (ret != SBCOK) {
        //Print(L"FW ID generate fail \n");
        goto errdone;
    }

    //SBC_mem_print_bin("Firmware ID", h->fwid, sizeof h->fwid);

    ret = SBC_GenOSID(ImageHandle,  h->fwid, h->osid);
    if (ret != SBCOK) {
        //Print(L"FW ID generate fail \n");
        goto errdone;
    }

    //SBC_mem_print_bin("OSID", h->osid, sizeof h->osid);
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

#ifdef _ALL_PASS_
   sbc_err_sysprn(SBC_LOG_CMN_PRIO_INFO, 2,
                 SYS_LOG_HOST_BOOT,
                 SYS_LOG_APP_NAME,
                 SYS_LOG_CSC_NAME,
                 0,
                 L"Detetion",
                 L"SBC_VENDOR_SP Factory SSBL Forced Running"); 
  SBC_SSBL_LoadAndStart(ImageHandle);
  return SBCOK;
#endif

  SBC_RET_VALIDATE_ERRCODEMSG((blkhnd != NULL), SBCNULLP, "Block I/O Handle Nill");

  startlba = ((BOOT_SECTOR3_OFS | BOOT_SSBL_OFS) >> SBC_RAWPRT_DFLT_SHIFT);

#if 1 //ndef _ALL_PASS_
//#error "ALL PASSED ENABLE not COmpile"
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
 
//imglen = ALIGN_VALUE(imglen, SBC_RAWPRT_DFLT_BLK_SZ);
//
//    dprint("After SSBL Image  (Addr : 0x%lx) Start LBA : 0x%lx, Len : %ld (0x%lx)",
//         (0 | BOOT_SSBL_OFS),
//         startlba,
//         imglen,
//         imglen);

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
    eprint("Factory SSBL File Create Fail");
    ret = SBCNOTFND;
    goto errdone;
  }
//
//ret = SBC_RawPrtReadBlock(blkhnd, (void *)loadimg, &imglen, startlba);
//if (ret != SBCOK) {
//  //Print(L"SSBL Factory Block Read Fail \n");
//  goto errdone;
//}
//
//if ((hndlcnt = SBC_FindEfiFileSystemProtocol(&ssbl_img_hndl)) <= 0) {
//  //Print(L"File SYstem Handle Found fail \n");
//  ret = SBCIO;
//  goto errdone;
//}
//
//
//_lv_set_data(&wrlv,&loadimg[4], imglen - 4);
//
//
////for (int idx = 0; idx < hndlcnt; idx++) {
//  retval = SBC_WriteFile(ssbl_img_hndl[0], fname, &wrlv);
////  if (EFI_ERROR(retval)) {
////      ret = SBCIO;
////      continue;
////      //goto errdone;
////  }
//
////  break;
////}
//
//if (EFI_ERROR(retval)) {
//  eprint("%s file write fail %r", fname, retval);
//  ret = SBCIO;
//  goto errdone;
//}
//
//

  //Print(L"SSBL Write is Done \n");
  //SBC_mem_print_bin("SSBL Header", imghdr, imglen);
#ifndef _FSBL_TEST_
  if (tmp_prtheader->keymode != KEY_MODE_NORMAL) {
    tmp_prtheader->keymode = KEY_MODE_NORMAL;


    CopyMem(imghdr, tmp_prtheader, sizeof(rawprt_hdr_t));

    //SBC_external_mem_print_bin("Write Partition Header", imghdr, 512);

    //ret = SBC_RawPrtBlockWrite(h_blkio, (UINT8 *)imghdr, SBC_RAWPRT_DFLT_BLK_SZ, 0);
    //SBC_RET_VALIDATE_ERRCODEMSG((ret == SBCOK), ret, "Key mode change fail");
  }
#endif 
  ret = SBC_SSBL_LoadAndStart(ImageHandle);
  if (ret != SBCOK) {
    //Print(L"SSBL Factory Running Fail \n");
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

#ifndef _ALL_PASS_

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

UINTN SBC_LogUnicodeSPrint (
  OUT CHAR16        *StartOfBuffer,
  IN  UINTN         BufferSize,
  IN  CONST CHAR16  *FormatString,
  ...
  )
{
  VA_LIST  Marker;
  UINTN    NumberOfPrinted;

  VA_START (Marker, FormatString);
  NumberOfPrinted = UnicodeVSPrint (StartOfBuffer, BufferSize, FormatString, Marker);
  VA_END (Marker);
  return NumberOfPrinted;
}


extern  VOID SBC_LogInternalX(IN CHAR8 *fmt,...);
EFI_HANDLE sbcImgHandle;

UINTN
IntToUnicodeStringManual (
  IN INT64        Value,
  OUT CHAR16      *StringBuffer,
  IN UINTN        BufferSize
  )
{
  CHAR16  *Ptr = StringBuffer;
  CHAR16  TempChar;
  UINTN   Count = 0;
  BOOLEAN IsNegative = FALSE;
  UINT64  AbsValue; // 절대값을 저장할 부호 없는 타입

  // 입력 유효성 검사
  if (StringBuffer == NULL || BufferSize == 0) {
    DEBUG((DEBUG_ERROR, "IntToUnicodeStringManual: Invalid input parameters (buffer or size).\n"));
    return 0;
  }

  // 버퍼가 Null-terminator를 포함할 수 있도록 최소 1 CHAR16 공간이 필요합니다.
  if (BufferSize < sizeof(CHAR16)) {
      DEBUG((DEBUG_ERROR, "IntToUnicodeStringManual: Buffer too small for null terminator.\n"));
      return 0;
  }

  // 음수 처리
  if (Value < 0) {
    IsNegative = TRUE;
    AbsValue = (UINT64)(-Value); // 음수의 절대값
  } else {
    AbsValue = (UINT64)Value;
  }

  // 0인 경우 특별 처리
  if (AbsValue == 0) {
    if (BufferSize < 2 * sizeof(CHAR16)) { // '0' + null terminator
        DEBUG((DEBUG_ERROR, "IntToUnicodeStringManual: Buffer too small for '0'.\n"));
        return 0;
    }
    *Ptr++ = L'0';
    Count = 1;
  } else {
    // 숫자를 역순으로 버퍼에 채웁니다.
    while (AbsValue > 0 && Count < (BufferSize / sizeof(CHAR16)) - 1) { // -1 for null terminator
      *Ptr++ = (CHAR16)(L'0' + (AbsValue % 10));
      AbsValue /= 10;
      Count++;
    }
  }

  // 음수인 경우 '-' 부호를 추가합니다.
  if (IsNegative) {
    if (Count < (BufferSize / sizeof(CHAR16)) - 1) { // -1 for null terminator
      *Ptr++ = L'-';
      Count++;
    } else {
      // 버퍼가 너무 작아 음수 부호를 추가할 수 없는 경우
      DEBUG((DEBUG_ERROR, "IntToUnicodeStringManual: Buffer too small for negative sign.\n"));
      // 이 경우 부분적으로 변환된 문자열이 남을 수 있으므로 0을 반환하거나 오류 처리 필요
      // 여기서는 Null-terminator를 추가하고 현재까지의 Count를 반환합니다.
      *Ptr = L'\0';
      return 0; // 또는 Count를 반환하여 부분 변환을 알림
    }
  }

  // Null-terminator 추가
  *Ptr = L'\0';

  // 문자열 역순 정렬
  // 시작 포인터는 StringBuffer, 끝 포인터는 Null-terminator 바로 앞
  CHAR16 *Start = StringBuffer;
  CHAR16 *End = StringBuffer + Count - 1; // Count는 부호까지 포함된 길이

  if (IsNegative) { // 음수인 경우 부호는 그대로 두고 숫자 부분만 역순 정렬
    Start++; // 부호 다음부터 시작
  }

  while (Start < End) {
    TempChar = *Start;
    *Start = *End;
    *End = TempChar;
    Start++;
    End--;
  }

  return Count;
}

/**
  가변 인자를 받아 포맷된 유니코드 문자열을 콘솔에 출력하는 사용자 정의 함수입니다.
  이 함수는 //PrintLib의 //Print() 함수와 유사하게 작동하지만,
  간단한 포맷 지정자 (%d, %s)만 지원합니다.

  @param  Format          유니코드 포맷 문자열입니다 (예: L"Hello %s, Value: %d\n").
  @param  ...             포맷 문자열에 해당하는 가변 인자들입니다.

  @retval EFI_STATUS      출력 작업의 상태입니다.
**/
EFI_STATUS
EFIAPI
SBC_LogCustomPrint (
  OUT CHAR16 *OutFormat,
  IN CONST CHAR16 *Format,
  ...
  )
{
  VA_LIST     Args;
  CHAR16      Buffer[256] = {0, }; // 출력 버퍼 (충분한 크기 할당)
  CHAR16      *BufferPtr = OutFormat;
  CONST CHAR16 *FormatPtr = Format;
  EFI_STATUS  Status = EFI_SUCCESS;
  UINTN       RemainingBufferSize = sizeof(Buffer);
  UINT32      CopyCnt = 0;

  // 입력 유효성 검사
  if (Format == NULL) {
    DEBUG((DEBUG_ERROR, "SBC_LogCustomPrint: Format string is NULL.\n"));
    return EFI_INVALID_PARAMETER;
  }

  // 가변 인자 목록 초기화
  VA_START(Args, Format);

  // 포맷 문자열을 파싱하며 버퍼에 문자열을 구성합니다.
  while (*FormatPtr != L'\0' && RemainingBufferSize > sizeof(CHAR16)) { // Null-terminator 공간 확보
    CopyCnt++;
    if (*FormatPtr == L'%') {
      FormatPtr++; // '%' 다음 문자로 이동

      switch (*FormatPtr) {
        case L'd': // 10진수 정수
          {
            INTN Value = VA_ARG(Args, INTN); // 다음 인자를 INTN으로 가져옴
            CHAR16 TempNumBuffer[30]; // 숫자를 문자열로 변환할 임시 버퍼
            UINTN NumChars;

            NumChars = IntToUnicodeStringManual(Value, TempNumBuffer, sizeof(TempNumBuffer));
            if (NumChars > 0) {
              // 임시 버퍼의 내용을 메인 버퍼로 복사
              UINTN CopySize = NumChars * sizeof(CHAR16);
              if (CopySize < RemainingBufferSize) {
                CopyMem(BufferPtr, TempNumBuffer, CopySize);
                BufferPtr += NumChars;
                RemainingBufferSize -= CopySize;
              } else {
                // 버퍼 오버플로우 처리
                DEBUG((DEBUG_ERROR, "SBC_LogCustomPrint: Buffer overflow for %%d.\n"));
                Status = EFI_BUFFER_TOO_SMALL;
                goto Exit; // 오류 발생 시 종료
              }
            }
          }
          break;
        case L's': // 유니코드 문자열
          {
            CHAR16 *Str = VA_ARG(Args, CHAR16*); // 다음 인자를 CHAR16*으로 가져옴
            UINTN StrLen = 0;
            CHAR16 *TempStrPtr = Str;

            if (Str == NULL) {
                Str = L"(null)"; // NULL 포인터 처리
            }

            while (*TempStrPtr != L'\0') {
              StrLen++;
              TempStrPtr++;
            }

            UINTN CopySize = StrLen * sizeof(CHAR16);
            if (CopySize < RemainingBufferSize) {
              CopyMem(BufferPtr, Str, CopySize);
              BufferPtr += StrLen;
              RemainingBufferSize -= CopySize;
            } else {
              // 버퍼 오버플로우 처리
              DEBUG((DEBUG_ERROR, "SBC_LogCustomPrint: Buffer overflow for %%s.\n"));
              Status = EFI_BUFFER_TOO_SMALL;
              goto Exit; // 오류 발생 시 종료
            }
          }
          break;
        case L'%': // '%%' 이스케이프 시퀀스
          if (RemainingBufferSize >= 2 * sizeof(CHAR16)) {
            *BufferPtr++ = L'%';
            RemainingBufferSize -= sizeof(CHAR16);
          } else {
            DEBUG((DEBUG_ERROR, "SBC_LogCustomPrint: Buffer too small for '%%'.\n"));
            Status = EFI_BUFFER_TOO_SMALL;
            goto Exit;
          }
          break;
        default: // 알 수 없는 포맷 지정자
          DEBUG((DEBUG_INFO,"SBC_LogCustomPrint: Unknown format specifier '%%%c'.\n", *FormatPtr));
          // 알 수 없는 지정자는 그대로 출력하거나 무시
          if (RemainingBufferSize >= 2 * sizeof(CHAR16)) {
            *BufferPtr++ = L'%';
            *BufferPtr++ = *FormatPtr;
            RemainingBufferSize -= 2 * sizeof(CHAR16);
          } else {
            DEBUG((DEBUG_ERROR, "SBC_LogCustomPrint: Buffer too small for unknown specifier.\n"));
            Status = EFI_BUFFER_TOO_SMALL;
            goto Exit;
          }
          break;
      }
    } else {
      // 일반 문자 복사
      if (RemainingBufferSize >= 2 * sizeof(CHAR16)) {
        *BufferPtr++ = *FormatPtr;
        RemainingBufferSize -= sizeof(CHAR16);
      } else {
        DEBUG((DEBUG_ERROR, "SBC_LogCustomPrint: Buffer too small for normal character.\n"));
        Status = EFI_BUFFER_TOO_SMALL;
        goto Exit;
      }
    }
    FormatPtr++;
  }

Exit:
  // Null-terminator 추가
  *BufferPtr = L'\0';

  // 가변 인자 목록 정리
  VA_END(Args);

  // 구성된 문자열을 콘솔에 출력
  if (!EFI_ERROR(Status)) {
    Status = gST->ConOut->OutputString(gST->ConOut, Buffer);
  } else {
    // 오류 발생 시 디버그 메시지만 출력
    DEBUG((DEBUG_ERROR, "SBC_LogCustomPrint: Failed to format string, attempting to //Print partial buffer.\n"));
    gST->ConOut->OutputString(gST->ConOut, Buffer); // 부분적으로라도 출력 시도
  }

  return Status;
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
    else {
      sbc_err_sysprn(SBC_LOG_CMN_PRIO_INFO, 2,
                   SYS_LOG_HOST_BOOT,
                   SYS_LOG_APP_NAME,
                   SYS_LOG_CSC_NAME,
                   0,
                   L"Detection",
                   L"Loaded to the Serial Driver");
    }

    gBS->Stall(50000);   // 50ms 지연
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
    else {
      sbc_err_sysprn(SBC_LOG_CMN_PRIO_INFO, 2,
                   SYS_LOG_HOST_BOOT,
                   SYS_LOG_APP_NAME,
                   SYS_LOG_CSC_NAME,
                   0,
                   L"Detection",
                   L"Loaded to the FTDI USB Serial Driver");

      //sleep(1);
    }

    gBS->Stall(50000);   // 50ms 지연
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
    else {

      sbc_err_sysprn(SBC_LOG_CMN_PRIO_INFO, 2,
                   SYS_LOG_HOST_BOOT,
                   SYS_LOG_APP_NAME,
                   SYS_LOG_CSC_NAME,
                   0,
                   L"Detection",
                   L"Loaded to the Terminal Dxe Driver");

      //sleep(1);
    }

    gBS->Stall(50000);   // 50ms 지연
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
    else {
      sbc_err_sysprn(SBC_LOG_CMN_PRIO_INFO, 2,
                   SYS_LOG_HOST_BOOT,
                   SYS_LOG_APP_NAME,
                   SYS_LOG_CSC_NAME,
                   0,
                   L"Detection",
                   L"Loaded to the XF64 Driver");

      //sleep(3);
    }
    gBS->Stall(50000);   // 50ms 지연
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


#ifdef _SHELL_CMD_LINE_
typedef struct {
    CHAR16 *BootMode;
    CHAR16 *KeyMode;
    CHAR16 *LoadImg;
} SBC_SHELL_OPTIONS;

/**
 * @code
 * if ((val = MatchLongOption(arg, L"--bootmode"))) {
            Opts->BootMode = val;
        } else if ((val = MatchLongOption(arg, L"--keymode"))) {
 *          Opts->KeyMode = val;
 *      }
 * 
 * @endcode
 * 
 * @author leoc (11/4/25)
 * 
 * @param Arg    
 * @param Name   
 * 
 * @return CHAR16* 
 */
CHAR16* MatchLongOption(IN CHAR16 *Arg, IN CONST CHAR16 *Name)
{
    UINTN len = StrLen(Name);
    if (StrnCmp(Arg, Name, len) == 0 && Arg[len] == L'=') {
        return &Arg[len + 1];
    }
    return NULL;
}

EFI_STATUS CopyHugeFileToRawFS(CHAR16 *Src, UINTN ofs)
{
    return EFI_SUCCESS;
}

EFI_STATUS ParseShellOptions(VOID *hndl)
{
    EFI_STATUS Status;
    EFI_SHELL_PARAMETERS_PROTOCOL *ShellParams;
    boot_proc_t *bp = (boot_proc_t *)hndl;

    SBCStatus ret = SBCOK;

    //anj
    cmd_dprint("Locate Shell Parameters Protocol");
    //
    Status = gBS->OpenProtocol(
        bp->imghndl,
        &gEfiShellParametersProtocolGuid,
        (VOID **)&ShellParams,
        bp->imghndl,
        NULL,
        EFI_OPEN_PROTOCOL_GET_PROTOCOL
    );

    if (EFI_ERROR(Status)) {
        Print(L"ShellParametersProtocol not available (%r)\n", Status);
        return EFI_NOT_FOUND;
    }

    //
    // Parse arguments
    //
    for (UINTN i = 1; i < ShellParams->Argc; i++) {
        CHAR16 *arg = ShellParams->Argv[i];

        cmd_dprint("arg : %s", arg);
        
//      CHAR16 *val = NULL;
//
//      if ((val = MatchLongOption(arg, -L"--loadimg"))) {
//      }

        if (!StrCmp(arg, L"--loadimg")) {
            if (i + 2 < ShellParams->Argc) {
                CHAR16 *LoadImgName;   
                [[maybe_unused]] UINT64  LoadImgAddr;
                UINTN   FileSize;
                EFI_STATUS retval = EFI_SUCCESS;

                LoadImgName = ShellParams->Argv[++i];
                LoadImgAddr = StrHexToUint64(ShellParams->Argv[++i]);


                
                ret = SBC_GetFileSize(LoadImgName, &FileSize);
                if (ret != SBCOK) {
                    cmd_eprint("Can't found the %s", LoadImgName);
                    return EFI_UNSUPPORTED;
                }

                cmd_dprint("Load Image Name: %s (size %d), Load Image : 0x%lx\n", LoadImgName, FileSize, LoadImgAddr );
                retval = SBC_CopyFileToBlockDevice(LoadImgName,
                                                   bp->blkhnd,
                                                   LoadImgAddr,
                                                   &FileSize);


                if (EFI_ERROR(retval)) {
                    cmd_eprint("Copy fail from %s to 0x%lx %r", LoadImgName, LoadImgAddr, retval);
                    return retval;
                }

                SBC_RebootSystem();

            }
          }
          else if (!StrCmp(arg, L"--dumpimg")) {
              if (i + 2 < ShellParams->Argc) {
                  UINT8 *blob = NULL;
                  UINTN LoadBlkAddr = StrHexToUint64(ShellParams->Argv[++i]);
                  UINTN LoadBlkLen = StrDecimalToUintn(ShellParams->Argv[++i]);

                  cmd_dprint("Load Addr : 0x%lx, Load Length : %d", LoadBlkAddr, LoadBlkLen);

                  blob = AllocateZeroPool(LoadBlkLen);
                  if (blob == NULL) {
                    cmd_eprint("Out of Resource !!!");
                    return EFI_UNSUPPORTED;
                  }

                  ret = SBC_RawAlignedReadBlockIO(bp->blkhnd, 
                                                  LoadBlkAddr,
                                                  LoadBlkLen,
                                                  blob);
                  if (ret != SBCOK) {
                    return EFI_UNSUPPORTED;
                  }

                  
                  SBC_external_mem_print_bin("Dump", blob, (UINT32)LoadBlkLen);

              }
          }
          else if (!StrCmp(arg, L"--bootmode")) {
            if (i + 2 < ShellParams->Argc) {
                UINT8 bkm_buf[16] = {0, };
                UINTN bm = StrDecimalToUintn(ShellParams->Argv[++i]);
                UINTN km = StrDecimalToUintn(ShellParams->Argv[++i]);
                //UINTN rcvm = StrDecimalToUintn(ShellParams->Argv[++i]);

                //bp->rcvmode = rcvm;

                ret = SBC_BootKeyModeChange(bm, km, (VOID *)bp);
                if (ret != SBCOK) {
                    cmd_eprint("Failed to Boot and Key Mode change bm:%d , km:%d", bm, km);
                    return EFI_UNSUPPORTED;
                }

                ret = SBC_RawAlignedReadBlockIO(bp->blkhnd, 
                                                0x70,
                                                16,
                                                bkm_buf);
                if (ret != SBCOK) {
                    cmd_eprint("Failed to Read (0x%lx)", 0x70);
                    return EFI_UNSUPPORTED;
                }

                
                SBC_external_mem_print_bin("Dump", bkm_buf, 16);

            }
          }
          else if (!StrCmp(arg, L"--nvramwrite")) {
                cmd_dprint("NVMwrite Argc : %d , i+2 : %d", ShellParams->Argc, i + 2);
                if (i + 2 < ShellParams->Argc ) {
                    EFI_STATUS retval = EFI_SUCCESS;
                    CHAR16 *varname = ShellParams->Argv[++i];
                    UINTN nv_varbuf = StrHexToUint64(ShellParams->Argv[++i]);
                    UINTN nv_varsz = sizeof nv_varbuf;

                    cmd_dprint("NVRAM write command ~~ running");

                    retval = SBC_NvramSetVar((VOID *)varname, (VOID *)&nv_varbuf, (VOID*)&nv_varsz);
                    if (EFI_ERROR(retval)) {
                        Print(L"Faile to NVRAM Set Variable \n");
                        return EFI_UNSUPPORTED;
                    }
                }
          }
          else if (!StrCmp(arg, L"--nvramread")) {
                cmd_dprint("Nvmread Argc : %d , i+2 : %d", ShellParams->Argc, i + 1);
                if (i + 1 < ShellParams->Argc) {
                    EFI_STATUS retval = EFI_SUCCESS;
                    CHAR16 *varname = ShellParams->Argv[++i];
                    UINTN nv_varbuf = 0ULL;
                    UINTN nv_varsz = 0ULL;

                    cmd_dprint("NVRAM read command ~~ running");

                    retval = SBC_NvramGetVar((VOID *)varname, (VOID *)&nv_varbuf, (VOID*)&nv_varsz);
                    if (EFI_ERROR(retval)) {
                        Print(L"Faile to NVRAM Get Variable \n");
                        return EFI_UNSUPPORTED;
                    }

                    Print(L"NVRAM Variable Name : %s \n", varname);
                    Print(L"NVRAM Variable Value : 0x%x \n", nv_varbuf);
                }
          }

        

    }

    return EFI_SUCCESS;
}
#endif

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
    //rawprt_hdr_t tmp_prtheader;    // Raw Partition Header handle
    
    //UINT32 pres_hi = 0;
    UINT32 pres_low = 0;
    UINT32 currbank_id = 0;
    UINT32 prevbank_id = 0;
    __attribute__((unused)) UINT32 bootmd = 0; // Boot Mode
    LV_t baseansr;
    [[maybe_unused]] UINTN testid = 0xAA55AA55;

    [[gnu::unused]] EFI_HANDLE ssbl_img_hndl = NULL;

    unit_proc_t btproc;

    UINTN driver_load_ns = 0ULL;

//  UINTN change_bm = BOOT_MODE_NORMAL;
//  UINTN change_km = KEY_MODE_NORMAL;


#ifdef _UNIT_TEST_ON_
    CHAR16 *varname = L"SBCBOOTORDER";
    UINTN boot_oredr_mode = 0;
#endif


    SBC_LogFileInit(ImageHandle);
 
    sys_start_time = SBC_PerfNowTicks();

    SBC_TIME_BLOCKS_NS (driver_load_ns,
        { retval = SBC_DrveriInit(); });

    ret = SBC_DeleteFile (EFI_BOOT_SSBL_PATH);
     if (ret == SBCNOTFND) {
             sbc_err_sysprn(SBC_LOG_CMN_PRIO_INFO, 2,
                  SYS_LOG_HOST_BOOT,
                  SYS_LOG_APP_NAME,
                  SYS_LOG_CSC_NAME,
                  0,
                  L"Detetion",
                  L"SBC_VENDOR_SP Can not found \\EFI\\BOOT\\SSBL.efi \n");
     }

     if ((ret != SBCOK) && (ret != SBCNOTFND )) {
             sbc_err_sysprn(SBC_LOG_CMN_PRIO_ERR, 2,
                  SYS_LOG_HOST_BOOT,
                  SYS_LOG_APP_NAME,
                  SYS_LOG_CSC_NAME,
                  0,
                  L"Detetion",
                  L"SBC_VENDOR_SP Failed to delete the \\EFI\\BOOT\\SSBL.efi \n");
             goto errdone;
     }

     sbc_err_sysprn(SBC_LOG_CMN_PRIO_INFO, 2,
                  SYS_LOG_HOST_BOOT,
                  SYS_LOG_APP_NAME,
                  SYS_LOG_CSC_NAME,
                  0,
                  L"Detetion",
                  L"SBC_VENDOR_SP Success to delete the \\EFI\\BOOT\\SSBL.efi \n");


    retval =  MapRebuild();
    if (EFI_ERROR(retval)) {
      sbc_err_sysprn(SBC_LOG_CMN_PRIO_INFO, 2,
                 SYS_LOG_HOST_BOOT,
                 SYS_LOG_APP_NAME,
                 SYS_LOG_CSC_NAME,
                 0,
                 L"Detetion",
                 L"SBC_VENDOR_SP Faile to Reconnect to All controller \n");
    }
    else {
      sbc_err_sysprn(SBC_LOG_CMN_PRIO_INFO, 2,
                 SYS_LOG_HOST_BOOT,
                 SYS_LOG_APP_NAME,
                 SYS_LOG_CSC_NAME,
                 0,
                 L"Detetion",
                 L"SBC_VENDOR_SP Success to Reconnect to All controller \n");
    }
//#ifdef _DEBUG_PRINT_ON_
//    PrintMappingTable();
//#endif

    SBC_LogElapsedTime(L"SBC Driver Load", driver_load_ns);
    sbc_err_sysprn(SBC_LOG_CMN_PRIO_INFO, 2,
                 SYS_LOG_HOST_BOOT,
                 SYS_LOG_APP_NAME,
                 SYS_LOG_CSC_NAME,
                 0,
                 L"Detetion",
                 L"SBC_VENDOR_SP FSBL Statring");

    btproc.bootst = TRUE;

    ZeroMem(&btproc, sizeof btproc);
    ZeroMem(&h_rawprtheader, sizeof h_rawprtheader);

#ifdef _SBC_TPM_
    UINT8      RandBuf[32];
    retval = SBC_TpmInit();
    if (EFI_ERROR(retval)) {
        sbc_err_sysprn(SBC_LOG_CMN_PRIO_INFO, 2,
                     SYS_LOG_HOST_BOOT,
                     SYS_LOG_APP_NAME,
                     SYS_LOG_CSC_NAME,
                     0,
                     L"Detetion",
                     L"SBC_VENDOR_SP TPM Init not OK \n");

        goto errdone;
    }

    sbc_err_sysprn(SBC_LOG_CMN_PRIO_INFO, 2,
                     SYS_LOG_HOST_BOOT,
                     SYS_LOG_APP_NAME,
                     SYS_LOG_CSC_NAME,
                     0,
                     L"Detetion",
                     L"SBC_VENDOR_SP TPM Init OK \n");

    //retval= SBC_DumpTpmFixedProperties();
    retval = SBC_PrintTpmVersionInfo();
    if (EFI_ERROR(retval)) {
        sbc_err_sysprn(SBC_LOG_CMN_PRIO_INFO, 2,
                     SYS_LOG_HOST_BOOT,
                     SYS_LOG_APP_NAME,
                     SYS_LOG_CSC_NAME,
                     0,
                     L"Detetion",
                     L"SBC_VENDOR_SP TPM Version found \n");

        goto errdone;
    }

    sbc_err_sysprn(SBC_LOG_CMN_PRIO_INFO, 2,
                     SYS_LOG_HOST_BOOT,
                     SYS_LOG_APP_NAME,
                     SYS_LOG_CSC_NAME,
                     0,
                     L"Detetion",
                     L"SBC_VENDOR_SP TPM Version found \n");

    for (int rndlp = 0; rndlp < 10; rndlp++) {
        retval = SBC_TpmGetRandom(RandBuf, sizeof(RandBuf));
        SBC_external_mem_print_bin("TPM Random", RandBuf, sizeof(RandBuf));
    }

    return EFI_SUCCESS;
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
                 L"SBC_VENDOR_SP Block I/O Init Fail");
      goto errdone;
    }

    tmp_prtheader = &h_rawprtheader;
    // Check the Preference SSBL bank
    CopyMem((void *)&pres_low, (void *)&h_rawprtheader.bootpres[0], 4);
    //CopyMem((void *)&pres_hi, (void *)&h_rawprtheader.bootpres[4], 4);

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


    
    //
    // Added by Leon
    // Run from Recovry Mode 
    //
    btproc.rcvmode = h_rawprtheader.rcvmode;
    btproc.b_forced = FALSE;

    tmp_btproc = &btproc;

    dprint("Boot Mode is %d", h_rawprtheader.bootmode);
    ZeroMem(mrgmsg, sizeof mrgmsg);
    UnicodeSPrint(mrgmsg, sizeof mrgmsg, L"SBC_SP_FW FSBL Boot Mode (0x%x) And Key Mode (0x%x) Recovery Mode (0x%x) \n", 
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

#ifdef _UNIT_TEST_ON_
//#   error "unit test mode"    
    dprint("============= Unit Test Starting =============");
    UINTN  varsz =  0;
    retval = SBC_NvramGetVar((VOID *)varname, (VOID *)&boot_oredr_mode, (VOID *)&varsz);
    if (EFI_ERROR(retval)) {
      UINTN bt_order = SBC_BOOT_SHDN_SFR_003;
      UINTN bt_varsz = sizeof bt_order;
      retval = SBC_NvramSetVar((VOID *)varname, (VOID *)&bt_order, (VOID *)&bt_varsz);
      SBC_RebootSystem();
    }

    //retval = SBC_NvramGetVar((VOID *)varname, (VOID *)&boot_oredr_mode, (VOID *)&varsz);

    Print(L"Boot Order : 0x%04x\n", boot_oredr_mode);
    //return EFI_SUCCESS; 

    //SBC_BiosReadBootOrder();
//#ifdef _UNIT_TEST_SFR001_TO_003_
    if (boot_oredr_mode == SBC_BOOT_SHDN_SFR_003) {
      UINTN bt_order = SBC_BOOT_SHDN_SFR_006;
      UINTN bt_varsz = sizeof bt_order;
      retval = SBC_NvramSetVar((VOID *)varname, (VOID *)&bt_order, (VOID *)&bt_varsz);
      SBC_UnitTestSFR001_TO_003((void *)&btproc);
    }
//#endif

//#ifdef _UNIT_TEST_SFR008_FSBL_
    if (boot_oredr_mode == SBC_BOOT_SHDN_SFR_006) {
      UINTN bt_order = SBC_BOOT_SHDN_SFR_006_TAMPER;
      UINTN bt_varsz = sizeof bt_order;
      retval = SBC_NvramSetVar((VOID *)varname, (VOID *)&bt_order, (VOID *)&bt_varsz);
      SBC_UnitFsblNormalTamperTest((void *)&btproc);

      sbc_err_sysprn(SBC_LOG_CMN_PRIO_NOTICE, 2,
         L"AT_BOOT",
         L"FSBL",
         L"SAT",
         6,
         L"Validation",
         L"SBC_Integrity_All boot components passed signature verification");
  //#endif
    }

    if (boot_oredr_mode == SBC_BOOT_SHDN_SFR_006_TAMPER) {
      UINTN bt_order = SBC_BOOT_SHDN_SFR_003;
      UINTN bt_varsz = sizeof bt_order;
      retval = SBC_NvramSetVar((VOID *)varname, (VOID *)&bt_order, (VOID *)&bt_varsz);
    //#ifdef _UNIT_TEST_SFR008_ABNORMAL_FSBL_
      extern void SBC_UnitFsblAbNormalTamperTest(void *priv);
      SBC_UnitFsblAbNormalTamperTest((void *)&btproc);

      

      sbc_err_sysprn(SBC_LOG_CMN_PRIO_NOTICE, 2,
         L"AT_BOOT",
         L"FSBL",
         L"SAT",
         6,
         L"Validation",
         L"SBC_tamper_FSBL_SSBL_OS signature verification faied");


      dprint("Unit Test Finish !!!!");
//endif
    }


//unit_test_done:
    return EFI_SUCCESS;
#else

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
                 L"SBC_tamper_ FSBL signature verification faied\n");
          retval = EFI_INVALID_PARAMETER;
          btproc.b_forced = TRUE;
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
             L"SBC_Dice_Key HW&SW Base Key Creation Fail");
        retval = EFI_INVALID_PARAMETER;
        btproc.bootst = SB_PROC_ST_ABNRAM;
        btproc.b_forced = TRUE;
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
                     L"SBC_tamper_ SSBL signature verification faied");

          btproc.bootst = SB_PROC_ST_ABNRAM;
          btproc.b_forced = TRUE;
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
                     SYS_LOG_EVT_VALDIATION,
                     L"SBC_tamper_SSBL signature verification suuccess");

        ret =  SBC_DeviceIdKyeVerify(h_blkio, diceid.devid, diceid.osid);
        if (ret != SBCOK) {
          sbc_err_sysprn(SBC_LOG_CMN_PRIO_ERR, 2,
                     SYS_LOG_HOST_BOOT,
                     SYS_LOG_APP_NAME,
                     SYS_LOG_CSC_NAME,
                     8,
                     L"EVT",
                     L"SBC_Dice_Verify Failed to Device ID verify");
          retval = EFI_INVALID_PARAMETER;
          btproc.bootst = SB_PROC_ST_ABNRAM;
          btproc.b_forced = TRUE;
#ifndef _ALL_PASS_
          goto errdone;
#endif
        }

        sbc_err_sysprn(SBC_LOG_CMN_PRIO_INFO, 2,
             SYS_LOG_HOST_BOOT,
             SYS_LOG_APP_NAME,
             SYS_LOG_CSC_NAME,
             8,
             SYS_LOG_EVT_VALDIATION,
             L"SBC_Integrity_All boot components passed signature verification \n");
#endif
#if 0
      //SBC_GRUB_LoadAndStart(NULL);         
      if ( btproc.rcvmode == 1 && btproc.prevmode == 1 ) {
        dprint(" Normal mode SSBL running on Previously bank");
        ret = SBC_BootModeNormalAndpUdate(h_blkio, ImageHandle, prevbank_id);
        if (ret != SBCOK) {
            eprint("BOOT_MODE_NORMAL Boot Fail");
            retval = EFI_INVALID_PARAMETER;
            btproc.bootst = SB_PROC_ST_ABNRAM;
            #ifndef _ALL_PASS_
            goto errdone;
            #endif
        }          
      }
      else if ( btproc.rcvmode == 1 && btproc.prevmode == 0 ){
        dprint(" Normal mode SSBL running on Factory bank");
        ret = SBC_BootModeFactory(h_blkio, ImageHandle);
        if (ret != SBCOK) {
              eprint("BOOT_MODE_FACTORY Boot Fail");
              //factory_md_abnormal_boot_state(&btproc);
              retval = EFI_INVALID_PARAMETER;
              btproc.bootst = SB_PROC_ST_ABNRAM;
            #ifndef _ALL_PASS_
              goto errdone;
            #endif
        }
      }
      else {
        dprint(" Normal mode SSBL running on Currently bank");
        ret = SBC_BootModeNormalAndpUdate(h_blkio, ImageHandle, currbank_id);
        if (ret != SBCOK) {
            eprint("BOOT_MODE_NORMAL Boot Fail");
            retval = EFI_INVALID_PARAMETER;
            btproc.bootst = SB_PROC_ST_ABNRAM;
            #ifndef _ALL_PASS_
            goto errdone;
            #endif
        }
      }
#else

        ret = SBC_RunSsblNormalScenario(
                &btproc,
                h_blkio,
                ImageHandle,
                currbank_id,
                prevbank_id
        );

        if (ret != SBCOK) {
                retval = EFI_INVALID_PARAMETER;
                btproc.b_forced = TRUE;
            #ifndef _ALL_PASS_
                goto errdone;
            #endif
        }
            #endif
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
                     L"SBC_tamper_ SSBL signature verification faied");
            btproc.bootst = SB_PROC_ST_ABNRAM;
            btproc.b_forced = TRUE;
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
                     SYS_LOG_EVT_VALDIATION,
                     L"SBC_tamper_SSBL signature verification suuccess");

      ret =  SBC_DeviceIdKyeVerify(h_blkio, diceid.devid, diceid.osid);
      //ret = SBCOK;
      if (ret != SBCOK) {
          sbc_err_sysprn(SBC_LOG_CMN_PRIO_ERR, 2,
                     SYS_LOG_HOST_BOOT,
                     SYS_LOG_APP_NAME,
                     SYS_LOG_CSC_NAME,
                     8,
                     SYS_LOG_EVT_DETECTION,
                     L"SBC_Dice_Verify Failed to Device ID verify");

          factory_md_abnormal_boot_state(&btproc);
          retval = EFI_INVALID_PARAMETER;
          btproc.bootst = SB_PROC_ST_ABNRAM;
          btproc.b_forced = TRUE;
#ifndef _ALL_PASS_
          goto errdone;
#endif
      }


      sbc_err_sysprn(SBC_LOG_CMN_PRIO_INFO, 2,
             SYS_LOG_HOST_BOOT,
             SYS_LOG_APP_NAME,
             SYS_LOG_CSC_NAME,
             8,
             SYS_LOG_EVT_VALDIATION,
             L"SBC_Integrity_All boot components passed signature verification \n");
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
                     L"SBC_tamper_ SSBL signature verification faied");
            btproc.bootst = SB_PROC_ST_ABNRAM;
            btproc.b_forced = TRUE;
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
                     SYS_LOG_EVT_VALDIATION,
                     L"SBC_tamper_SSBL signature verification suuccess");
#if 1
      ret =  SBC_DeviceIdKyeVerify(h_blkio, diceid.devid, diceid.migid);
      if (ret != SBCOK) {
          sbc_err_sysprn(SBC_LOG_CMN_PRIO_ERR, 2,
                     SYS_LOG_HOST_BOOT,
                     SYS_LOG_APP_NAME,
                     SYS_LOG_CSC_NAME,
                     8,
                     L"Detection",
                     L"SBC_Dice_Verify Failed to Device ID verify");
          retval = EFI_INVALID_PARAMETER;
          btproc.b_forced = TRUE;
          btproc.bootst = SB_PROC_ST_ABNRAM;
#ifndef _ALL_PASS_
          goto errdone;
#endif
      }
#endif



      sbc_err_sysprn(SBC_LOG_CMN_PRIO_INFO, 2,
             SYS_LOG_HOST_BOOT,
             SYS_LOG_APP_NAME,
             SYS_LOG_CSC_NAME,
             8,
             SYS_LOG_EVT_VALDIATION,
             L"SBC_Integrity_All boot components passed signature verification \n");
#endif     
      ret = SBC_BootModeNormalAndpUdate(h_blkio, ImageHandle, currbank_id);
      if (ret != SBCOK) {
          eprint("BOOT_MODE_UPDATE Boot Fail");
          retval = EFI_INVALID_PARAMETER;
          btproc.bootst = SB_PROC_ST_ABNRAM;
          btproc.b_forced = TRUE;
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
                     L"SBC_tamper_ SSBL signature verification faied");
            btproc.bootst = SB_PROC_ST_ABNRAM;
            btproc.b_forced = TRUE;
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
                     SYS_LOG_EVT_VALDIATION,
                     L"SBC_tamper_SSBL signature verification suuccess");

     ret =  SBC_DeviceIdKyeVerify(h_blkio, diceid.devid, diceid.migid);
     if (ret != SBCOK) {
          sbc_err_sysprn(SBC_LOG_CMN_PRIO_ERR, 2,
                     SYS_LOG_HOST_BOOT,
                     SYS_LOG_APP_NAME,
                     SYS_LOG_CSC_NAME,
                     8,
                     SYS_LOG_EVT_DETECTION,
                     L"SBC_Dice_Verify Failed to Device ID verify");
             retval = EFI_INVALID_PARAMETER;
             btproc.b_forced = TRUE;
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
             SYS_LOG_EVT_VALDIATION,
             L"SBC_Integrity_All boot components passed signature verification \n");
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

    SBC_LogElapsedTime(L"x FSBL Boot Time", sys_ns_var);
#ifndef _ALL_PASS_
    switch(h_rawprtheader.bootmode) {
    case BOOT_MODE_NORMAL:
    case BOOT_MODE_UPDATE:

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
        
    default:
        break;
    }

    SBC_ShutdownSystem();
#else 
    SBC_BootModeFactory(h_blkio, ImageHandle);
#endif
    return retval;
}

