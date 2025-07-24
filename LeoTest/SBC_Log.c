
#include <Uefi.h>
#include <Library/BaseMemoryLib.h>
#include <Library/UnitTestLib.h>
#include <Library/UefiLib.h>
//#include <Libray/RngLib.h>

#include <Library/BaseLib.h>
#include <Library/PrintLib.h>
#include <Library/HandleParsingLib.h>
#include <Library/ShellLib.h>

//#include <Library/UefiBootServicesTableLib.h>
//#include <Library/UefiRuntimeServceisTableLib.h>

#include <Library/UefiLib/UefiLibInternal.h>
#include <Library/PcdLib.h>

#include <stdio.h>
#include <stdlib.h>
#include <stdarg.h>

#include "SBC_Log.h"
#include "SBC_FileCtrl.h"

#define UNIT_TEST_MAX_LOG_BUFFER  SIZE_16KB

struct _UNIT_TEST_LOG_PREFIX_STRING {
  UNIT_TEST_STATUS    LogLevel;
  CHAR8               *String;
};

struct _UNIT_TEST_LOG_PREFIX_STRING  mLogPrefixStrings[] = {
  { UNIT_TEST_LOG_LEVEL_ERROR,   "[ERROR]       " },
  { UNIT_TEST_LOG_LEVEL_WARN,    "[WARNING]     " },
  { UNIT_TEST_LOG_LEVEL_INFO,    "[INFO]        " },
  { UNIT_TEST_LOG_LEVEL_VERBOSE, "[VERBOSE]     " }
};

#if 0


static void vcm_print_error(const char* const format, va_list args)
{
    char buffer[1024];
    size_t msg_len = 0;
    va_list ap;
    int len;
    va_copy(ap, args);

    len = vsnprintf(buffer, sizeof(buffer), format, args);
    if (len < 0) {
        /* TODO */
        goto end;
    }

    if (cm_error_message == NULL) {
        /* CREATE MESSAGE */

        cm_error_message = calloc(1, len + 1);
        if (cm_error_message == NULL) {
            /* TODO */
            goto end;
        }
    } else {
        /* APPEND MESSAGE */
        char *tmp;

        msg_len = strlen(cm_error_message);
        tmp = realloc(cm_error_message, msg_len + len + 1);
        if (tmp == NULL) {
            goto end;
        }
        cm_error_message = tmp;
    }

    if (((size_t)len) < sizeof(buffer)) {
        /* Use len + 1 to also copy '\0' */
        memcpy(cm_error_message + msg_len, buffer, len + 1);
    } else {
        vsnprintf(cm_error_message + msg_len, len, format, ap);
    }
end:
    va_end(ap);

}

void _fail(const char * const file, const int line) {
    enum cm_message_output output = cm_get_output();

    switch(output) {
        case CM_OUTPUT_STDOUT:
            cm_print_error("[   LINE   ] --- " SOURCE_LOCATION_FORMAT ": error: Failure!", file, line);
            break;
        default:
            cm_print_error(SOURCE_LOCATION_FORMAT ": error: Failure!", file, line);
            break;
    }
    //exit_test(1);

    /* Unreachable */
    exit(-1);
}

void cm_print_error(const char * const format, ...)
{
    va_list args;
    va_start(args, format);
    if (cm_error_message_enabled) {
        vcm_print_error(format, args);
    } else {
        vprint_error(format, args);
    }
    va_end(args);
}

void _assert_true(const LargestIntegralType result,
                  const char * const expression,
                  const char * const file, const int line) {
    if (!result) {
        cm_print_error("%s\n", expression);
        _fail(file, line);
    }
}


BOOLEAN SBC_Assert(BOOLEAN expression, CONST CHAR8 *funcname, UINTN linenumber, CONST CHAR8 *filename, CONST CHAR8 *description)
{
  CHAR8 tempstr[1025];
  snprintf (tempstr, sizeof (tempstr), "UT_ASSERT_TRUE(%s:%x)", description, expression);
  _assert_true (expression, , temstr, filename, (INT32)linenumber);

  return expression;

}
#endif


VOID SBC_LogBoolean(BOOLEAN expression, CONST CHAR8 *funcname, UINTN linenumber, CONST CHAR8 *filename, CONST CHAR8 *description)
{
  CHAR8 tempstr[1025];
  //snprintf (tempstr, sizeof (tempstr), "UT_ASSERT_TRUE(%s:%x)", description, expression);
  Print(L"%s \n", tempstr);


}

//VOID SBC_LogMsg(/*@unused@*/UINT8* logmsg ARG_UNUSED, CONST CHAR8 *funcname, UINTN linenumber, CONST CHAR8 *filename, CONST CHAR8 *description)
VOID SBC_LogMsg(CHAR8* logmsg , CONST CHAR8 *funcname, UINTN linenumber, CONST CHAR8 *filename)
{
  CHAR16 tempstr[1025] = {0, };
  UnicodeSPrint(tempstr, sizeof (tempstr), L"[%a:%a:%d] %a", filename, funcname, linenumber, logmsg);
  //CHAR8 tempstr[1025] = {0, };
  //snprintf(tempstr, sizeof (tempstr), "%s%s%lld%s", filename, funcname, linenumber, logmsg);
  //DEBUG((DEBUG_INFO, "%a", tempstr));
#if 1
  ShellPrintEx(
      -1,
      -1,
      tempstr,
      L""
      );
#endif




}

//extern EFI_STATUS SBC_LogWriteFile(EFI_HANDLE ImageHandle, CHAR16 *FileNames, LV_t *out);
//extern EFI_STATUS SBC_IsFlieAccess(EFI_HANDLE ImageHandle, CHAR16 *FileNames);
//extern EFI_STATUS SBC_IsDirExist(EFI_HANDLE ImageHandle, CHAR16 *DirName);
//
//
//void _sbc_write_log_file(CHAR8 *message, UINT32 msglen)
//{
//    EFI_STATUS Status;
//    SBCStatus ret = SBCOK;
//    EFI_HANDLE      *hndl = NULL;
//    EFI_HANDLE      loghnd = NULL;
//    UINTN           hndlcnt;
//    LV_t            wrlv;
//
//    CHAR16         *rocky_dir_name = L"\\EFI\\rocky";
//    CHAR16         *sbc_log_fname = L"\\EFI\\rocky\\sbc_fsbl_sys_log";
//
//    EFI_STATUS retval = EFI_SUCCESS;
//
//    hndlcnt = SBC_FindEfiFileSystemProtocol(&hndl);
//
//    //dprint("Log gEfiSimpleFileSystemProtocolGuid Handle Count :%d ", hndlcnt);
//
//    for (int idx = 0; idx < hndlcnt; idx++) {
//        //dprint("[idx:%d] handle addr : 0x%x", idx, hndl[idx]);
//        Status = SBC_IsDirExist(hndl[idx], rocky_dir_name);
//        switch (Status) {
//        case EFI_SUCCESS:
//          loghnd=  hndl[idx];
//          //dprint("%s dir exists \n", rocky_dir_name);
//          break;
//        case EFI_NOT_FOUND:
//          //dprint("%s dir not found \n", rocky_dir_name);
//          //dprint();
//          //goto errdone;
//          break;
//        default:
//          dprint("Unknown error (%s) \n", Status);
//          break;
//        }
//
//    }
//
//    if (loghnd == NULL) {
//        goto errdone;
//    }
//
//    Status = SBC_IsFlieAccess(loghnd, sbc_log_fname);
//    switch (Status) {
//    case EFI_SUCCESS:
//      break;
//    case EFI_NOT_FOUND:
//      // Create File
//      ret = SBC_CreateFile(loghnd, sbc_log_fname);
//      break;
//
//    default:
//      dprint("Unknown error (%s) \n", Status);
//      goto errdone;
//
//    }
//
//    if (ret != SBCOK) {
//        eprint("log file create fail \n");
//        return;
//    }
//
//
//    wrlv.value = message;
//    wrlv.length = msglen;
//
//    retval = SBC_LogWriteFile(loghnd, sbc_log_fname, &wrlv);
//    if (EFI_ERROR(retval)) {
//        dprint(" og  write fail (%r) \n",  retval);
//
//    }
//
//
//errdone:
//    return;
//
//}

UINTN
AsciiPrintToBuffer (
  IN  CONST CHAR8 *Format,
  ...
  )
{
 
  return 0;
}

UINTN
SBC_IntToUnicodeStringManual (
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



EFI_STATUS SBC_CustomPrint (
  IN CONST CHAR16 *Format,
  ...
  )
{
  VA_LIST     Args;
  CHAR16      Buffer[256]; // 출력 버퍼 (충분한 크기 할당)
  CHAR16      *BufferPtr = Buffer;
  CONST CHAR16 *FormatPtr = Format;
  EFI_STATUS  Status = EFI_SUCCESS;
  UINTN       RemainingBufferSize = sizeof(Buffer);

  // 입력 유효성 검사
  if (Format == NULL) {
    DEBUG((DEBUG_ERROR, "MyCustomPrint: Format string is NULL.\n"));
    return EFI_INVALID_PARAMETER;
  }

  // 가변 인자 목록 초기화
  VA_START(Args, Format);

  // 포맷 문자열을 파싱하며 버퍼에 문자열을 구성합니다.
  while (*FormatPtr != L'\0' && RemainingBufferSize > sizeof(CHAR16)) { // Null-terminator 공간 확보
    if (*FormatPtr == L'%') {
      FormatPtr++; // '%' 다음 문자로 이동

      switch (*FormatPtr) {
        case L'd': // 10진수 정수
          {
            INTN Value = VA_ARG(Args, INTN); // 다음 인자를 INTN으로 가져옴
            CHAR16 TempNumBuffer[30]; // 숫자를 문자열로 변환할 임시 버퍼
            UINTN NumChars;

            NumChars = SBC_IntToUnicodeStringManual(Value, TempNumBuffer, sizeof(TempNumBuffer));
            if (NumChars > 0) {
              // 임시 버퍼의 내용을 메인 버퍼로 복사
              UINTN CopySize = NumChars * sizeof(CHAR16);
              if (CopySize < RemainingBufferSize) {
                CopyMem(BufferPtr, TempNumBuffer, CopySize);
                BufferPtr += NumChars;
                RemainingBufferSize -= CopySize;
              } else {
                // 버퍼 오버플로우 처리
                DEBUG((DEBUG_ERROR, "MyCustomPrint: Buffer overflow for %%d.\n"));
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
              DEBUG((DEBUG_ERROR, "MyCustomPrint: Buffer overflow for %%s.\n"));
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
            DEBUG((DEBUG_ERROR, "MyCustomPrint: Buffer too small for '%%'.\n"));
            Status = EFI_BUFFER_TOO_SMALL;
            goto Exit;
          }
          break;
        default: // 알 수 없는 포맷 지정자
          DEBUG((DEBUG_INFO,"MyCustomPrint: Unknown format specifier '%%%c'.\n", *FormatPtr));
          // 알 수 없는 지정자는 그대로 출력하거나 무시
          if (RemainingBufferSize >= 2 * sizeof(CHAR16)) {
            *BufferPtr++ = L'%';
            *BufferPtr++ = *FormatPtr;
            RemainingBufferSize -= 2 * sizeof(CHAR16);
          } else {
            DEBUG((DEBUG_ERROR, "MyCustomPrint: Buffer too small for unknown specifier.\n"));
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
        DEBUG((DEBUG_ERROR, "MyCustomPrint: Buffer too small for normal character.\n"));
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
    DEBUG((DEBUG_ERROR, "MyCustomPrint: Failed to format string, attempting to print partial buffer.\n"));
    gST->ConOut->OutputString(gST->ConOut, Buffer); // 부분적으로라도 출력 시도
  }

  return Status;
}

VOID SBC_LogInternalX(IN CHAR8 *fmt,...)
{
    va_list args;
    UINTN fmtlen = 0;
    //VA_LIST marker;
    CHAR8 buf[512];

    //VA_START(marker, format);
    va_start(args, fmt);
    dprint();
    fmtlen = AsciiVSPrint(buf, sizeof buf, fmt, args);
    dprint("Fmt (%d) : %a", fmtlen, buf);
    va_end(args);

    //VA_END(marker);
}


VOID SBC_LogInternal(IN CHAR8 *fmt, IN va_list marker)
{
    UINTN fmtlen = 0;
    //VA_LIST marker;
    CHAR8 buf[512];

    //VA_START(marker, format);
    dprint();
    fmtlen = AsciiVSPrint(buf, sizeof buf, fmt, marker);
    dprint("Fmt (%d) : %s", fmtlen, buf);
    //VA_END(marker);
}

//static UINTN remove_all_space(CHAR8* str, UINTN cnt) {
//    UINTN write_index = 0;
//    UINTN read_index = 0;
//
//    while (read_index != cnt) {
//        if (str[read_index] != 0x00) {
//            str[write_index] = str[read_index];
//            write_index++;
//        }
//        read_index++;
//    }
//    str[write_index] = '\0';
//
//    return write_index;
//}

VOID SBC_LogVarIntMrg(CHAR16 *msg, UINT32 val, CHAR16 *msgout)
{
    UnicodeSPrint(msgout, StrLen(msg) + 4, L"%s:%d", (char *)msg, val);
}

UINTN SBC_LogFmtOutNoraml(IN CONST CHAR16 *fmt, ...)
{
    return 0;
}

UINTN SBC_LogFmtOut(OUT CHAR16 *outbuf, IN CONST CHAR16 *fmt, ...)
{
    VA_LIST marker;
    CHAR16 buf[8192];
    UINTN   retval;

    VA_START(marker, fmt);
    retval = UnicodeVSPrint(buf, sizeof(buf), fmt, marker);
    VA_END(marker);

    buf[retval] = '\0';

    CopyMem(outbuf, buf, retval);

    return retval;
}

//static CHAR8 full_log_msg[8192] = {0, };

//VOID  SBC_LogPrint(UINT32 prio, UINT32 ver, CHAR16 *host,
//                        CHAR16 *appname, CHAR16 *csc,
//                        UINT32 sfrid, CHAR16 *evtype,
//                        CHAR16 *message, CHAR16 *msgarg)
//{
//
//
//    [[gnu::unused]] VA_LIST args;
//    EFI_TIME logtime;
//    CHAR8 *wrlog = NULL;
//    CHAR16 full_log_msg[8192] = {0, };
//    UINTN nxtofs = 0;
//    UINTN endofs = sizeof full_log_msg;
//
//    ZeroMem(&logtime, sizeof(EFI_TIME));
//    gRT->GetTime(&logtime, NULL);
//
//    nxtofs +=  UnicodeSPrint(&full_log_msg[nxtofs], endofs , L"%d %d %d-%d-%dT%d:%d.%d %s %s %s",
//                             prio, ver,
//                             logtime.Year, logtime.Month, logtime.Day,
//                             logtime.Hour, logtime.Minute, logtime.Second,
//                             host, appname, csc);
//
//    endofs -= nxtofs;
//    nxtofs +=  UnicodeSPrint(&full_log_msg[nxtofs], endofs , L" R-SAT-PWT-SFR-%03d %s ",
//                             sfrid, evtype);
//
//
//    endofs -= nxtofs;
//    nxtofs += UnicodeSPrint(&full_log_msg[nxtofs], endofs, L"%s-%s", message, msgarg);
//
//
////  VA_START(args, format);
////
////  dprint("End of FS :  %lu", endofs);
////  //nxtofs += UnicodeVSPrint(&full_log_msg[nxtofs] , endofs, format, args);
////  nxtofs += UnicodeVSPrint(full_log_msg , endofs, format, args);
////  VA_END(args);
//
//
//
//    //Print(L"Mesage buf length : %d  , size : %d\n", StrnLenS(full_log_msg,8192), StrnSizeS(full_log_msg,8192));
//
//    wrlog = (CHAR8 *)full_log_msg;
//    Print(L"%s \n", full_log_msg);
//    nxtofs = remove_all_space(wrlog,StrnSizeS(full_log_msg,8192));
//    //SBC_mem_print_bin("Log", (UINT8 *)wrlog, nxtofs);
//
//    _sbc_write_log_file(wrlog,strlen(wrlog));
//
//
//
//}


//VOID  SBC_LogPrint(CONST CHAR16* func, UINT32 funcline, UINT32 prio, UINT32 ver, CHAR16 *host,
//                        CHAR16 *appname, CHAR16 *csc,
//                        UINT32 sfrid, CHAR16 *evtype,
//                        CHAR16 *message, CHAR16 *msgarg,
//                        CHAR16 *format, ...)
//{
//
//
//    [[gnu::unused]] VA_LIST args;
//    EFI_TIME logtime;
//    CHAR8 *wrlog = NULL;
//    CHAR16 full_log_msg[8192] = {0, };
//    UINTN nxtofs = 0;
//    UINTN endofs = sizeof full_log_msg;
//
//    ZeroMem(&logtime, sizeof(EFI_TIME));
//    gRT->GetTime(&logtime, NULL);
//
//    nxtofs +=  UnicodeSPrint(&full_log_msg[nxtofs], endofs , L"%d %d %d-%d-%dT%d:%d.%d %s %s %s",
//                             prio, ver,
//                             logtime.Year, logtime.Month, logtime.Day,
//                             logtime.Hour, logtime.Minute, logtime.Second,
//                             host, appname, csc);
//
//    endofs -= nxtofs;
//    nxtofs +=  UnicodeSPrint(&full_log_msg[nxtofs], endofs , L" R-SAT-PWT-SFR-%03d %s ",
//                             sfrid, evtype);
//
//
//    endofs -= nxtofs;
//    nxtofs += UnicodeSPrint(&full_log_msg[nxtofs], endofs, L"%s-%s", message, msgarg);
//
//
////  VA_START(args, format);
////
////  dprint("End of FS :  %lu", endofs);
////  //nxtofs += UnicodeVSPrint(&full_log_msg[nxtofs] , endofs, format, args);
////  nxtofs += UnicodeVSPrint(full_log_msg , endofs, format, args);
////  VA_END(args);
//
//
//
//    //Print(L"Mesage buf length : %d  , size : %d\n", StrnLenS(full_log_msg,8192), StrnSizeS(full_log_msg,8192));
//
//    wrlog = (CHAR8 *)full_log_msg;
//    nxtofs = remove_all_space(wrlog,StrnSizeS(full_log_msg,8192));
//    //SBC_mem_print_bin("Log", (UINT8 *)wrlog, nxtofs);
//    Print(L"[%a:%d] %a \n", func, funcline, wrlog);
//    _sbc_write_log_file(wrlog,strlen(wrlog));
//
//
//
//}


VOID  SBC_LogPrintX(UINT32 prio, UINT32 ver, CHAR16 *host, 
                        CHAR16 *appname, CHAR16 *csc,
                        UINT32 sfrid, CHAR16 *evtype,
                        CHAR16 *format, ...)
{

  return;
//  //CHAR16 buf[512];
//  //AR16 logtime[64];
//  [[gnu::unused]]VA_LIST args;
//  EFI_TIME logtime;
//  CHAR8 *wrlog = NULL;
//  CHAR16 full_log_msg[512] = {0, };
//  //CHAR16 sfr_id_buf[16] = {0, };
//  //CHAR16 time_buf[128] = {0, };
//
//  UINTN nxtofs = 0;
//
//  UINTN endofs = sizeof full_log_msg;
//
//
//
//  ZeroMem(&logtime, sizeof(EFI_TIME));
//  gRT->GetTime(&logtime, NULL);
//
//  //nxtofs=  UnicodeSPrint(full_log_msg, endofs, L"[%a:%d]", func, funcline);
//
//  //endofs -= nxtofs;
//  nxtofs +=  UnicodeSPrint(&full_log_msg[nxtofs], endofs , L"%d %d %d-%d-%dT%d:%d.%d %s %s %s",
//                           prio, ver,
//                           logtime.Year, logtime.Month, logtime.Day,
//                           logtime.Hour, logtime.Minute, logtime.Second,
//                           host, appname, csc);
//
//  endofs -= nxtofs;
//  nxtofs +=  UnicodeSPrint(&full_log_msg[nxtofs], endofs , L" R-SAT-PWT-SFR-%03d %s ",
//                           sfrid, evtype);
//
//
//  endofs -= nxtofs;
//
//
//  va_start(args, format);
//  nxtofs += UnicodeVSPrint(&full_log_msg[nxtofs] , endofs, format, args);
//  va_end(args);
//
//
//
//  //Print(L"Mesage buf length : %d  , size : %d\n", StrnLenS(full_log_msg,8192), StrnSizeS(full_log_msg,8192));
//
//  wrlog = (CHAR8 *)full_log_msg;
//  nxtofs = remove_all_space(wrlog,StrnSizeS(full_log_msg,8192));
//  //SBC_mem_print_bin("Log", (UINT8 *)wrlog, nxtofs);
//  Print(L"Full Log msg : %a \n", wrlog);
//  _sbc_write_log_file(wrlog,strlen(wrlog));
//
    

}

VOID  SBC_LogWrite(UINT32 prio, CHAR16 *ver, CHAR16 *host, 
                        CHAR16 *appname, CHAR16 *csc,
                        UINT32 sfrid, CHAR16 *evtype,
                        CONST CHAR16 *format, ...)
{

//  VA_LIST marker;
//  CHAR16 buf[512];
//  //AR16 logtime[64];
//  EFI_TIME logtime;
//  CHAR16 full_log_msg[1024] = {0, };
//  CHAR16 sfr_id_buf[16] = {0, };
//
//  VA_START(marker, format);
//
//  UnicodeVSPrint(buf, sizeof buf, format, marker);
//
//
//  ZeroMem(&logtime, sizeof(EFI_TIME));
//  gRT->GetTime(&logtime, NULL);
//
//  UnicodeVSPrint(sfr_id_buf, sizeof sfr_id_buf , L"SFR-%ld", sfrid);
//
//
//  UnicodeVSPrint(full_log_msg, sizeof full_log_msg,
//                 L"<%d> %s %d %d-%d-%dT%d:%d.$d %s %s %s %s %s %s",
//                 priortiy, ver,
//                 logtime.Year,logtime.Month,logtime.Day,
//                 logtime.Hour,logtime.Minute,logtime.Second,
//                 host, appname, cs, sfr_id_buf,evtype,
//                 buf
//  );
//
//
//  VA_END(marker);
//
    //Print(L"%s \n", CHAR16);

    return;
}

#define LINE_LEN 16
void SBC_mem_print_bin(
        CHAR8 *title /**< [in] display name strings */,
        UINT8* buffer /**< [in] print buffer  */,
        UINT32 length /**< [in] length of buffer */
        )
{
    UINT32 i, sz;

    if(title) {
        Print(L"%a (length of buffer: %d) \r\r\n", title, length) ;
    }

    if (!buffer) {
        Print(L"\tNULL\r\n");
        return;
    }

    while (length > 0) {
        sz = length;
        if (sz > LINE_LEN)
            sz = LINE_LEN;

        Print(L"\t");
        for (i = 0; i < LINE_LEN; i++) {
            if (i < length)
                Print(L"%02x ", buffer[i]);
            else
                Print(L"   ");
        }
        Print(L"| ");
        for (i = 0; i < sz; i++) {
            if (buffer[i] > 31 && buffer[i] < 127)
                Print(L"%c", buffer[i]);
            else
                Print(L".");
        }
        Print(L"\r\r\n");


        buffer += sz;
        length -= sz;
    }
}


void SBC_external_mem_print_bin(
        CHAR8 *title /**< [in] display name strings */,
        UINT8* buffer /**< [in] print buffer  */,
        UINT32 length /**< [in] length of buffer */
        )
{
    UINT32 i, sz;
    UINT32 offset = 0;

    if(title) {
        DEBUG((DEBUG_INFO,"%a (length of buffer: %d) \r\r\n", title, length)) ;
    }

    if (!buffer) {
        return;
    }

    while (length > 0) {
        sz = length;
        if (sz > LINE_LEN)
            sz = LINE_LEN;

        DEBUG((DEBUG_INFO," [0x%08X] :  ", offset));
        for (i = 0; i < LINE_LEN; i++) {
            if (i < length)
                DEBUG((DEBUG_INFO,"%02x ", buffer[i]));
            else
                DEBUG((DEBUG_INFO,"   "));
        }
        DEBUG((DEBUG_INFO," | "));
        for (i = 0; i < sz; i++) {
            if (buffer[i] > 31 && buffer[i] < 127)
                DEBUG((DEBUG_INFO,"%c", buffer[i]));
            else
                DEBUG((DEBUG_INFO,"."));
        }
        offset += LINE_LEN;
        DEBUG((DEBUG_INFO,"\r\n"));


        buffer += sz;
        length -= sz;
    }
}


