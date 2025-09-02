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


VOID *h_blkio;               // Block I/O handle
#ifndef _FSBL_TEST_
static rawprt_hdr_t *tmp_prtheader;    // Raw Partition Header handle
#endif
static BOOLEAN        is_boot_status; 

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

    (VOID)ImageHandle;


    h = (atp_ident_t *)p;

    ret = SBC_GenDeviceID(h->devid);
    if (ret != SBCOK) {
        Print(L"Device ID generate fail \n");
        goto errdone;
    }
//
    SBC_mem_print_bin("Device ID", h->devid, sizeof h->devid);
    ret = SBC_GenFWID(ImageHandle, h->devid, h->fwid, normbank, bm);
    if (ret != SBCOK) {
        Print(L"FW ID generate fail \n");
        goto errdone;
    }

    SBC_mem_print_bin("Firmware ID", h->fwid, sizeof h->fwid);

    ret = SBC_GenOSID(ImageHandle,  h->fwid, h->osid);
    if (ret != SBCOK) {
        Print(L"FW ID generate fail \n");
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
  

  EFI_HANDLE  *ssbl_img_hndl;
  [[maybe_unused]]UINTN endlba = 0;
  [[maybe_unused]]INTN       hndlcnt = 0;
  __attribute__((unused))EFI_STATUS retval;
  CHAR16 *fname = L"\\EFI\\BOOT\\SSBL.efi";


  LV_t wrlv;

  SBC_RET_VALIDATE_ERRCODEMSG((blkhnd != NULL), SBCNULLP, "Block I/O Handle Nill");

  startlba = ((BOOT_SECTOR3_OFS | BOOT_SSBL_OFS) >> SBC_RAWPRT_DFLT_SHIFT);


  ret = SBC_RawPrtReadBlock(blkhnd, (void *)imghdr, &imglen, startlba);
  if (ret != SBCOK) {
    Print(L"SSBL Factory Block Read Fail \n");
    goto errdone;
  }




  CopyMem((void *)&imglen, &imghdr[0], sizeof imglen);

 
  imglen = ALIGN_VALUE(imglen, SBC_RAWPRT_DFLT_BLK_SZ);

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


  _lv_set_data(&wrlv,&loadimg[4], imglen - 4);

#if 1
  //for (int idx = 0; idx < hndlcnt; idx++) {
    retval = SBC_WriteFile(ssbl_img_hndl[0], fname, &wrlv);
  //  if (EFI_ERROR(retval)) {
  //      ret = SBCIO;
  //      continue;
  //      //goto errdone;
  //  }

  //  break;
  //}

  if (EFI_ERROR(retval)) {
    eprint("%s file write fail %r", fname, retval);
    ret = SBCIO;
    goto errdone;
  }



  Print(L"SSBL Write is Done \n");
  //SBC_mem_print_bin("SSBL Header", imghdr, imglen);
#ifndef _FSBL_TEST_
  if (tmp_prtheader->keymode != KEY_MODE_NORMAL) {
    tmp_prtheader->keymode = KEY_MODE_NORMAL;


    CopyMem(imghdr, tmp_prtheader, sizeof(rawprt_hdr_t));

    SBC_external_mem_print_bin("Write Partition Header", imghdr, 512);

    //ret = SBC_RawPrtBlockWrite(h_blkio, (UINT8 *)imghdr, SBC_RAWPRT_DFLT_BLK_SZ, 0);
    //SBC_RET_VALIDATE_ERRCODEMSG((ret == SBCOK), ret, "Key mode change fail");
  }
#endif 
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
  [[gnu::unused]]CHAR16 *fname = L"\\EFI\\BOOT\\SSBL.efi";
  int idx;



  LV_t wrlv;
  //UINT8 *imgssbl = NULL;

  dprint("----- Normal Boot SSBL running ( Bank Id : 0x%x ) -----", nrombank);

  SBC_RET_VALIDATE_ERRCODEMSG((nrombank > 0 && nrombank < 3), SBCINVPARAM, "Invalid Parameter for SSBL bank");
  SBC_RET_VALIDATE_ERRCODEMSG((blkhnd != NULL), SBCNULLP, "Block I/O Handle Nill");

  bsofs = (BOOT_SECTOR1_OFS | ((nrombank - 1) << 20));
  startlba = ((bsofs | BOOT_SSBL_OFS) >> SBC_RAWPRT_DFLT_SHIFT);

  ret = SBC_RawPrtReadBlock(blkhnd, (void *)imghdr, &imglen, startlba);
  if (ret != SBCOK) {
    Print(L"SSBL Factory Block Read Fail \n");
    goto errdone;
  }


  CopyMem((void *)&imglen, &imghdr[0], sizeof imglen);
 
  imglen = ALIGN_VALUE(imglen, SBC_RAWPRT_DFLT_BLK_SZ);
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

  //  for (idx = 0; idx < hndlcnt; idx++) {
  //
  ////  retval = SBC_IsFlieAccess(ssbl_img_hndl[idx], fname);
  ////  dprint("[%d] ret value : %r", idx , retval);
  ////  if (EFI_ERROR(retval)) {
  ////    continue;
  ////  }
  //
  //
  //    BOOLEAN bret = FALSE;
  //
  //
  //    bret = SBC_IsDirExist(ssbl_img_hndl[idx], L"\\EFI\\rocky");
  //    dprint("bret : %d , idx : %d", bret, idx);
  //    if (bret != TRUE) {
  //      continue;
  //    }
  //
  //    break;
  //  }


  for (int idx = 0; idx < hndlcnt; idx++) {
    retval = SBC_WriteFile(ssbl_img_hndl[idx], fname, &wrlv);
    if (EFI_ERROR(retval)) {
        continue;
        //goto errdone;
    }

    break;
  }

  if (EFI_ERROR(retval)) {
    ret = SBCNOTFND;
    //continue;
    goto errdone;
  }
  dprint("idx : %d , hndlecount : %d", idx, hndlcnt);
  Print(L"SSBL Write is Done \n");
  //SBC_mem_print_bin("SSBL Header", imghdr, imglen);
  
  ret = SBC_SSBL_LoadAndStart(ImageHandle);
  if (ret != SBCOK) {
    Print(L"SSBL  Running Fail \n");
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
  이 함수는 PrintLib의 Print() 함수와 유사하게 작동하지만,
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
    DEBUG((DEBUG_ERROR, "SBC_LogCustomPrint: Failed to format string, attempting to print partial buffer.\n"));
    gST->ConOut->OutputString(gST->ConOut, Buffer); // 부분적으로라도 출력 시도
  }

  return Status;
}

CHAR16 mrgmsg[8192]; 



extern VOID SBC_ShutdownSystem(VOID);
extern SBCStatus SBC_GRUB_LoadAndStart(EFI_HANDLE ImageHandle);
extern EFI_STATUS SBC_LodaDriver(CONST CHAR16 *FileName, CONST BOOLEAN  Connect);


EFI_STATUS
EFIAPI
UefiMain (
//EntryPoint(
  IN EFI_HANDLE        ImageHandle,
  IN EFI_SYSTEM_TABLE  *SystemTable
  )
{

#define SERIAL_DXE_PATH                 L"\\EFI\\BOOT\\SerialDxe.efi"
#define FTDI_USB_SERIAL_DXE_PATH        L"\\EFI\\BOOT\\FtdiUsbSerialDxe.efi"
#define TERMINAL_DXE_PATH               L"\\EFI\\BOOT\\TerminalDxe.efi"
#define XFS64_PATH                      L"\\EFI\\BOOT\\xfs_x64.efi"

    atp_ident_t diceid;
    EFI_STATUS retval = EFI_SUCCESS;
    SBCStatus  ret = SBCOK;
    rawprt_hdr_t h_rawprtheader;    // Raw Partition Header handle
    //rawprt_hdr_t tmp_prtheader;    // Raw Partition Header handle
    
    UINT32 pres_hi = 0;
    UINT32 pres_low = 0;
    UINT32 currbank_id = 0;
    UINT32 prevbank_id = 0;
    __attribute__((unused)) UINT32 bootmd = 0; // Boot Mode
    LV_t baseansr;
    [[maybe_unused]] UINTN testid = 0xAA55AA55;

    [[gnu::unused]] EFI_HANDLE ssbl_img_hndl = NULL;

    unit_proc_t btproc;

#ifdef _SBC_DRIVER_LOAD_
    retval = SBC_LodaDriver(SERIAL_DXE_PATH, TRUE);
    if (EFI_ERROR (retval)){
      Print(L"SERIAL_DXE_PATH Dxe driver load fail \n");
      goto errdone;
    }


    //sleep(1);

    retval = SBC_LodaDriver(FTDI_USB_SERIAL_DXE_PATH, TRUE);
    if (EFI_ERROR (retval)){
      Print(L"FTDI_USB_SERIAL_DXE_PATH Dxe driver load fail \n");
      goto errdone;
    }

    //sleep(1);
    retval = SBC_LodaDriver(TERMINAL_DXE_PATH, TRUE);
    if (EFI_ERROR (retval)){
      Print(L"TERMINAL_DXE_PATH Dxe driver load fail \n");
      goto errdone;
    }

    //sleep(1);
    retval = SBC_LodaDriver(XFS64_PATH, TRUE);
    if (EFI_ERROR (retval)){
      Print(L"XFS64_PATH Dxe driver load fail \n");
      goto errdone;
    }

    //sleep(3);
#endif


#ifndef _FSBL_TEST_ 
    dprint("------------- FSBL START -------------\n");
#else
    dprint("------------- FSBL Test Mode START !!! -------------\n");
#endif    

    is_boot_status = TRUE;



    ZeroMem(&btproc, sizeof btproc);
    ZeroMem(&h_rawprtheader, sizeof h_rawprtheader);

    btproc.bootst = SB_PROC_ST_NRMA;
    // Get the NVMe SSD Raw Partiton handle and Header information
    ret = SBC_BlkIoHandleInit(&h_blkio, &h_rawprtheader);
    if (ret != SBCOK) {
      Print(L"Raw Partitino find fail !!! \n");
      goto errdone;
    }
#if 0
    btproc.blkhnd = h_blkio;
    btproc.rawprt_hdr = &h_rawptrheader;
    SBC_mem_print_bin("Raw Prt Header", (UINT8 *)&h_rawptrheader, sizeof h_rawptrheader);


    SBC_BootKeyModeChange(BOOT_MODE_FACTORY, KEY_MODE_NORMAL, (void *)&btproc);


    return EFI_SUCCESS;
#endif
    tmp_prtheader = &h_rawprtheader;
    //CopyMem(&tmp_prtheader, &h_rawprtheader, sizeof(rawprt_hdr_t));

    //dprint("Partition Header Information :");
    //SBC_external_mem_print_bin("Raw Partitino Header", (UINT8 *)&h_rawprtheader, sizeof(rawprt_hdr_t));

    // Check the Preference SSBL bank
    CopyMem((void *)&pres_low, (void *)&h_rawprtheader.bootpres[0], 4);
    CopyMem((void *)&pres_hi, (void *)&h_rawprtheader.bootpres[4], 4);

    pres_low = SBC_SWAP_ENDIAN_32(pres_low);
    pres_hi = SBC_SWAP_ENDIAN_32(pres_hi);


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
    dprint("Boot Mode : %d", h_rawprtheader.bootmode);

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

   // Step 1-1 )  FSBL, self sign and verify
    SBC_AntiTamperingInit(NULL);

    //return EFI_SUCCESS; 

#ifdef _UNIT_TEST_ON_
//#   error "unit test mode"    
    dprint("============= Unit Test Starting =============");
#ifdef _UNIT_TEST_SFR001_TO_003_
    SBC_UnitTestSFR001_TO_003((void *)&btproc);
#endif

#ifdef _UNIT_TEST_SFR008_FSBL_
    SBC_UnitFsblNormalTamperTest((void *)&btproc);
#endif

#ifdef _UNIT_TEST_SFR008_ABNORMAL_FSBL_
    extern void SBC_UnitFsblAbNormalTamperTest(void *priv);
    SBC_UnitFsblAbNormalTamperTest((void *)&btproc);
#endif


    dprint("Unit Test Finish !!!!");


    return EFI_SUCCESS;
#else

    ret = SBC_FSBL_Verify(h_blkio, &baseansr, currbank_id, h_rawprtheader.bootmode,STR_FSBL_F_NAME);
    if (ret != SBCOK) {
          is_boot_status = FALSE;
          btproc.bootst = SB_PROC_ST_ABNRAM;
          retval = EFI_INVALID_PARAMETER;
          goto errdone;
    }

    ZeroMem(mrgmsg, sizeof mrgmsg);
    UnicodeSPrint(mrgmsg, sizeof mrgmsg, L"FSBL Verify Success %s\n", baseansr.value);
    sbc_err_sysprn(SBC_LOG_CMN_PRIO_ERR, 2,
         L"SBC",
         L"FSBL",
         L"Weapon System",
         8,
         L"Determine Firmare Tampering ",
         mrgmsg);
  
    


    ret = SBC_DiceKeysGen(ImageHandle, &diceid, currbank_id, h_rawprtheader.bootmode);
    if (ret != SBCOK) {
        //sbc_err_sysprn(SBC_LOG_CMN_PRIO_ERR, 2, L"SBC", L"FSBL", L"Weapon System", 4, L"EVT", L"Dice Key creation fail\n");
        retval = EFI_INVALID_PARAMETER;
        is_boot_status = FALSE;
        btproc.bootst = SB_PROC_ST_ABNRAM;
        goto errdone;
    }

#ifdef _FSBL_FACTORY_TEST_
    dprint("Boot Mode is %d", h_rawprtheader.bootmode);
    h_rawprtheader.bootmode  = BOOT_MODE_FACTORY;
#endif

    
    switch (h_rawprtheader.bootmode) {
    case BOOT_MODE_NORMAL:
      dprint("Boot Mode is BOOT_MODE_NORMAL");
#ifdef _SBC_DEVID_VERIFY_
      ret = SBC_SSBL_Verify(h_blkio, NULL, currbank_id, BOOT_MODE_NORMAL);
      if (ret != SBCOK) {
            sbc_err_sysprn(SBC_LOG_CMN_PRIO_ERR, 2,
                   L"SBC",
                   L"FSBL",
                   L"Weapon System",
                   8,
                   L"Determine Firmare Tampering ",
                   L"SSBL tampering check fail");
            is_boot_status = FALSE;
            retval = EFI_INVALID_PARAMETER;
            //goto errdone;
      }

      sbc_err_sysprn(SBC_LOG_CMN_PRIO_ERR, 2,
       L"SBC",
       L"FSBL",
       L"Weapon System",
       8,
       L"Determine Firmare Tampering ",
       L"SSBL tampering check Done");

      ret =  SBC_DeviceIdKyeVerify(h_blkio, diceid.devid, diceid.osid);
      if (ret != SBCOK) {
              sbc_err_sysprn(SBC_LOG_CMN_PRIO_ERR, 2, 
                     L"SBC", 
                     L"FSBL", 
                     L"Weapon System", 
                     8, 
                     L"EVT", 
                     L"Device ID verify fail ");
              retval = EFI_INVALID_PARAMETER;
              is_boot_status = FALSE;
              goto errdone;
      }
#endif         

      ret = SBC_BootModeNormalAndpUdate(h_blkio, ImageHandle, currbank_id);
      if (ret != SBCOK) {
          eprint("Normal Boot Fail");
          retval = EFI_INVALID_PARAMETER;
          is_boot_status = FALSE;
          goto errdone;
      }
      break;
    case BOOT_MODE_FACTORY:
      //Print(L"Factory Boot Mode !!! \n");

#ifdef _SBC_DEVID_VERIFY_
      ret = SBC_SSBL_Verify(h_blkio, NULL, currbank_id, BOOT_MODE_FACTORY);
      if (ret != SBCOK) {
            sbc_err_sysprn(SBC_LOG_CMN_PRIO_ERR, 2,
                   L"SBC",
                   L"SSBL",
                   L"Weapon System",
                   8,
                   L"Determine Firmare Tampering ",
                   L"SSBL tampering check fail");
            is_boot_status = FALSE;
            retval = EFI_INVALID_PARAMETER;
            //goto errdone;
      }

      sbc_err_sysprn(SBC_LOG_CMN_PRIO_ERR, 2,
       L"SBC",
       L"SSBL",
       L"Weapon System",
       8,
       L"Determine Firmare Tampering ",
       L"SSBL tampering check Done");


      ret =  SBC_DeviceIdKyeVerify(h_blkio, diceid.devid, diceid.osid);
      if (ret != SBCOK) {
//            sbc_err_sysprn(SBC_LOG_CMN_PRIO_ERR, 2,
//                   L"SBC",
//                   L"FSBL",
//                   L"Weapon System",
//                   8,
//                   L"EVT",
//                   L"Device ID verify fail ");
              retval = EFI_INVALID_PARAMETER;
              is_boot_status = FALSE;
              goto errdone;
      }
#endif     

      ret = SBC_BootModeFactory(h_blkio, ImageHandle);
      if (ret != SBCOK) {
          eprint("Factory Boot Fail");
          retval = EFI_INVALID_PARAMETER;
          is_boot_status = FALSE;
          goto errdone;
      }
//    if (is_boot_status != TRUE) {
//      goto errdone;
//    }
//      // Change the key mode to normal based on key mode behavior scenario.
//    if (tmp_prtheader->keymode != KEY_MODE_NORMAL) {
//      tmp_prtheader->keymode = KEY_MODE_NORMAL;
//      SBC_RawPrtBlockWrite(h_blkio, (UINT8 *)&tmp_prtheader, sizeof(rawprt_hdr_t), 0);
//    }
//
//    //ret = SBC_SSBL_LoadAndStart(ssbl_img_hndl);
//    ret = SBC_GRUB_LoadAndStart(ssbl_img_hndl);
//    if (ret != SBCOK) {
//      goto errdone;
//    }

      //Print(L"Factory BOot Mode end !!! \n");
      break;
    case BOOT_MODE_UPDATE:
#ifdef _SBC_DEVID_VERIFY_

      ret = SBC_SSBL_Verify(h_blkio, NULL, currbank_id, BOOT_MODE_UPDATE);
      if (ret != SBCOK) {
            sbc_err_sysprn(SBC_LOG_CMN_PRIO_ERR, 2,
                   L"SBC",
                   L"FSBL",
                   L"Weapon System",
                   8,
                   L"Determine Firmare Tampering ",
                   L"FSBL tampering check fail");
            is_boot_status = FALSE;
            retval = EFI_INVALID_PARAMETER;
            //goto errdone;
      }

     sbc_err_sysprn(SBC_LOG_CMN_PRIO_ERR, 2,
       L"SBC",
       L"FSBL",
       L"Weapon System",
       8,
       L"Determine Firmare Tampering ",
       L"FSBL tampering check Done");

      ret =  SBC_DeviceIdKyeVerify(h_blkio, diceid.devid, diceid.migid);
      if (ret != SBCOK) {
//            sbc_err_sysprn(SBC_LOG_CMN_PRIO_ERR, 2,
//                   L"SBC",
//                   L"FSBL",
//                   L"Weapon System",
//                   8,
//                   L"EVT",
//                   L"Device ID verify fail ");
              retval = EFI_INVALID_PARAMETER;
              is_boot_status = FALSE;
              goto errdone;
      }
#endif     
      ret = SBC_BootModeNormalAndpUdate(h_blkio, ImageHandle, currbank_id);
      if (ret != SBCOK) {
          eprint("Normal Boot Fail");
          retval = EFI_INVALID_PARAMETER;
          is_boot_status = FALSE;
          goto errdone;
      }

      break;
    case BOOT_MODE_RECOVERY:

#ifdef _SBC_DEVID_VERIFY_

      ret = SBC_SSBL_Verify(h_blkio, NULL, prevbank_id, BOOT_MODE_RECOVERY);
      if (ret != SBCOK) {
            sbc_err_sysprn(SBC_LOG_CMN_PRIO_ERR, 2,
                   L"SBC",
                   L"FSBL",
                   L"Weapon System",
                   8,
                   L"Determine Firmare Tampering ",
                   L"FSBL tampering check fail");
            is_boot_status = FALSE;
            retval = EFI_INVALID_PARAMETER;
            //goto errdone;
      }

     sbc_err_sysprn(SBC_LOG_CMN_PRIO_ERR, 2,
       L"SBC",
       L"FSBL",
       L"Weapon System",
       8,
       L"Determine Firmare Tampering ",
       L"FSBL tampering check Done");

      ret =  SBC_DeviceIdKyeVerify(h_blkio, diceid.devid, diceid.migid);
      if (ret != SBCOK) {
//            sbc_err_sysprn(SBC_LOG_CMN_PRIO_ERR, 2,
//                   L"SBC",
//                   L"FSBL",
//                   L"Weapon System",
//                   8,
//                   L"EVT",
//                   L"Device ID verify fail ");
              retval = EFI_INVALID_PARAMETER;
              is_boot_status = FALSE;
              goto errdone;
      }
#endif  

      // Previously Boot FW loading 
      ret = SBC_BootModeNormalAndpUdate(h_blkio, ImageHandle, prevbank_id);
      if (ret != SBCOK) {
          eprint("Normal Boot Fail");
          retval = EFI_INVALID_PARAMETER;
          is_boot_status = FALSE;
          goto errdone;
      }
      break;
    default:
      Print(L"Unknown (%d)  Boot Mode ... SHOULD go to Abort\n",h_rawprtheader.bootmode);
      is_boot_status = FALSE;
      break;
    }


    //ret = SBC_FSBL_Verify(h_blkio, &baseansr);

  // Read SSBL from



  // Access bank addr ( (0x200 + (128 << 20)) * currbank_id )
#endif

errdone:

#ifndef _FSBL_TEST_ 
  // In terms of the Abnormal behavior on Factory Mode 
    if ((h_rawprtheader.bootmode == BOOT_MODE_FACTORY) && (is_boot_status != TRUE)) {
      // Change the key mode to normal based on key mode behavior scenario.
      if (tmp_prtheader->keymode != KEY_MODE_NORMAL) {
        tmp_prtheader->keymode = KEY_MODE_NORMAL;

        SBC_RawPrtBlockWrite(h_blkio, (UINT8 *)&tmp_prtheader, sizeof(rawprt_hdr_t), 0);
      }


      // Log write
     


    }

    SBC_ShutdownSystem();
#endif

    return retval;
}

