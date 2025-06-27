
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

#include <stdio.h>
#include <stdlib.h>
#include <stdarg.h>

#include "SBC_Log.h"

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

void _sbc_write_log_file(CHAR16 *message)
{
    EFI_SIMPLE_FILE_SYSTEM_PROTOCOL *fs;
    EFI_FILE_PROTOCOL *root, *log;

    EFI_STATUS retval = EFI_SUCCESS;

    retval = gBS->HandleProtocol(
                gImageHandle,
                &gEfiSimpleFileSystemProtocolGuid,
                (VOID **)&fs
        );

    if (EFI_ERROR(retval)) {
        Print(L"Log Handle Protocol found fail \n");
        return;
    }

    retval = fs->OpenVolume(fs, &root);
    if (EFI_ERROR(retval)) {
        Print(L"Log OpenVolume fail \n");
        return;
    }


    retval = root->Open(
                root,
                &log,
                L"\\EFI\\rocky\\log.txt",
                EFI_FILE_MODE_READ | EFI_FILE_MODE_WRITE | EFI_FILE_MODE_CREATE,
                0
        );

    if (EFI_ERROR(retval)) {
        Print(L"Log Open fail \n");
        return;
    }

    // Go to the end of the file
    retval = log->SetPosition(log, (UINT64)-1);

    UINTN bufsz = StrLen(message) * sizeof(CHAR16);

    retval = log->Write(log, &bufsz, message);
    log->Close(log);

}

VOID  SBC_LogPrint(CONST CHAR16* func, UINT32 funcline, UINT32 prio, UINT32 ver, CHAR16 *host, 
                        CHAR16 *appname, CHAR16 *csc,
                        UINT32 sfrid, CHAR16 *evtype,
                        CONST CHAR16 *format, ...)
{

    VA_LIST marker;
    //CHAR16 buf[512];
    //AR16 logtime[64];
    EFI_TIME logtime;
    CHAR16 full_log_msg[8<<10] = {0, };
    //CHAR16 sfr_id_buf[16] = {0, };
    //CHAR16 time_buf[128] = {0, };

    UINTN nxtofs = 0;
    UINTN fmtlen = 0;
    UINTN endofs = sizeof full_log_msg;

 

    ZeroMem(&logtime, sizeof(EFI_TIME));
    gRT->GetTime(&logtime, NULL);

    nxtofs=  UnicodeSPrint(full_log_msg, endofs, L"[%s:%d]", func, funcline);
    dprint("F1 : %s", full_log_msg);

    endofs -= nxtofs;
    nxtofs +=  UnicodeSPrint(&full_log_msg[nxtofs], endofs , L"%d %d %d-%d-%dT%d:%d.%d %s %s %s", 
                             prio, ver, 
                             logtime.Year, logtime.Month, logtime.Day,
                             logtime.Hour, logtime.Minute, logtime.Second,
                             host, appname, csc);
    dprint("F2 : %s", full_log_msg);

    endofs -= nxtofs;
    nxtofs +=  UnicodeSPrint(&full_log_msg[nxtofs], endofs , L" SFR-%d %s", 
                             sfrid, evtype);

    dprint("F3 : %s", full_log_msg);

    endofs -= nxtofs;
 
    VA_START(marker, format);
    fmtlen = UnicodeVSPrint(&full_log_msg[nxtofs], endofs, format, marker);
    dprint("Fmt (%d) : %s", fmtlen, full_log_msg);
    VA_END(marker);

   
    SBC_external_mem_print_bin("Log", (UINT8 *)full_log_msg, nxtofs);
//
//    nxtofs = AsciiSPrint(sfr_id_buf, sizeof sfr_id_buf , "SFR-%ld", sfrid);
//
//    //Print(L"Sfr id: %a \n", sfr_id_buf);
//
//    dprint("Offset : %d - SFR ID %a", nxtofs, sfr_id_buf);
//    nxtofs = AsciiSPrint(time_buf, sizeof  time_buf,
//                         "%d-%d-%dT%d:%d.%d",
//                         logtime.Year, logtime.Month, logtime.Day,
//                         logtime.Hour, logtime.Minute, logtime.Second);
//
//
//
//
//
//    dprint("Offset : %d - time %a", nxtofs, time_buf);
//
//
////  nxtofs = AsciiSPrint(full_log_msg, sizeof full_log_msg,
////                 "[%s:%d] <%d> %d %d %s %s %s %s %s %s",
////                 func, funcline,prio, ver, time_buf,
////                 host, appname, csc, sfr_id_buf,evtype
////  );
//    nxtofs = AsciiSPrint(full_log_msg, sizeof full_log_msg,
//                   "[%s:%d] <%d> %d %d %s %s %s %s %s %s",
//                   func, funcline,prio, ver, time_buf,
//                   host, appname, csc, sfr_id_buf,evtype
//    );
//
//    dprint("log header : %a", full_log_msg);
//
//    dprint("x2 offset : %d  %d\n", nxtofs, sizeof full_log_msg - nxtofs);
//    nxtofs += AsciiSPrint(&full_log_msg[nxtofs] , sizeof full_log_msg - nxtofs, format);
//
//    SBC_external_mem_print_bin("Log", (UINT8 *)full_log_msg, nxtofs);
//

    //VA_END(marker);

    Print(L"Full Log msg : %a \n", full_log_msg);

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
        DEBUG((DEBUG_INFO,"\r\r\n"));


        buffer += sz;
        length -= sz;
    }
}


