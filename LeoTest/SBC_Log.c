
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

extern EFI_STATUS SBC_LogWriteFile(EFI_HANDLE ImageHandle, CHAR16 *FileNames, LV_t *out);
extern EFI_STATUS SBC_IsFlieAccess(EFI_HANDLE ImageHandle, CHAR16 *FileNames);
extern EFI_STATUS SBC_IsDirExist(EFI_HANDLE ImageHandle, CHAR16 *DirName);


void _sbc_write_log_file(CHAR8 *message, UINT32 msglen)
{
    EFI_STATUS Status;
    SBCStatus ret = SBCOK;
    EFI_HANDLE      *hndl = NULL;
    EFI_HANDLE      loghnd = NULL;
    UINTN           hndlcnt;
    LV_t            wrlv;

    CHAR16         *rocky_dir_name = L"\\EFI\\rocky";
    CHAR16         *sbc_log_fname = L"\\EFI\\rocky\\sbc_fsbl_sys_log";

    EFI_STATUS retval = EFI_SUCCESS;

    hndlcnt = SBC_FindEfiFileSystemProtocol(&hndl);

    //dprint("Log gEfiSimpleFileSystemProtocolGuid Handle Count :%d ", hndlcnt);

    for (int idx = 0; idx < hndlcnt; idx++) {
        //dprint("[idx:%d] handle addr : 0x%x", idx, hndl[idx]);
        Status = SBC_IsDirExist(hndl[idx], rocky_dir_name);
        switch (Status) {
        case EFI_SUCCESS:
          loghnd=  hndl[idx];
          //dprint("%s dir exists \n", rocky_dir_name);
          break;
        case EFI_NOT_FOUND:
          //dprint("%s dir not found \n", rocky_dir_name);
          //dprint();
          //goto errdone;
          break;
        default:
          dprint("Unknown error (%s) \n", Status);
          break;
        }

    }

    if (loghnd == NULL) {
        goto errdone;
    }

    Status = SBC_IsFlieAccess(loghnd, sbc_log_fname);
    switch (Status) {
    case EFI_SUCCESS:
      break;
    case EFI_NOT_FOUND:
      // Create File 
      ret = SBC_CreateFile(loghnd, sbc_log_fname);
      break;
      
    default:
      dprint("Unknown error (%s) \n", Status);
      goto errdone;
      
    }

    if (ret != SBCOK) {
        eprint("log file create fail \n");
        return;
    }


    wrlv.value = message;
    wrlv.length = msglen;

    retval = SBC_LogWriteFile(loghnd, sbc_log_fname, &wrlv);
    if (EFI_ERROR(retval)) {
        dprint(" og  write fail (%r) \n",  retval);
        
    }

 
errdone:
    return;

}


UINTN
AsciiPrintToBuffer (
  IN  CONST CHAR16 *Format,
  ...
  )
{
  VA_LIST Marker;
  UINTN   Result =0;

  CHAR16      *xBuffer;
  UINTN       xBufferSize;

  VA_START(Marker, Format);
  xBufferSize = (PcdGet32 (PcdUefiLibMaxPrintBufferSize) + 1) * sizeof (CHAR16);
  dprint("Buffer size : %d", xBufferSize);


  xBuffer = (CHAR16 *)AllocatePool (xBufferSize);
 
  dprint("Buffer Addr : %p, Format addr  : %p", xBuffer, Format);

  //AsciiVSPrint(Buffer, sizeof(Buffer), Format, Marker);
  Result = UnicodeVSPrint (xBuffer, xBufferSize, Format, Marker);


  dprint("xbuferf : %s \n", xBuffer);

  FreePool(xBuffer);
  VA_END (Marker);
  return Result;
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

static UINTN remove_all_space(CHAR8* str, UINTN cnt) {
    UINTN write_index = 0; 
    UINTN read_index = 0;  

    while (read_index != cnt) {
        if (str[read_index] != 0x00) {
            str[write_index] = str[read_index];
            write_index++;
        }
        read_index++;
    }
    str[write_index] = '\0';

    return write_index;
}

VOID SBC_LogVarIntMrg(CHAR16 *msg, UINT32 val, CHAR16 *msgout)
{
    UnicodeSPrint(msgout, StrLen(msg) + 4, L"%s:%d", (char *)msg, val);
}

VOID  SBC_LogPrint(CONST CHAR16* func, UINT32 funcline, UINT32 prio, UINT32 ver, CHAR16 *host, 
                        CHAR16 *appname, CHAR16 *csc,
                        UINT32 sfrid, CHAR16 *evtype,
                        CHAR16 *format, ...)
{


    //CHAR16 buf[512];
    //AR16 logtime[64];
    va_list args;
    EFI_TIME logtime;
    CHAR8 *wrlog = NULL;
    CHAR16 full_log_msg[512] = {0, };
    //CHAR16 sfr_id_buf[16] = {0, };
    //CHAR16 time_buf[128] = {0, };

    UINTN nxtofs = 0;
    
    UINTN endofs = sizeof full_log_msg;

 

    ZeroMem(&logtime, sizeof(EFI_TIME));
    gRT->GetTime(&logtime, NULL);

    nxtofs=  UnicodeSPrint(full_log_msg, endofs, L"[%a:%d]", func, funcline);

    endofs -= nxtofs;
    nxtofs +=  UnicodeSPrint(&full_log_msg[nxtofs], endofs , L"%d %d %d-%d-%dT%d:%d.%d %s %s %s", 
                             prio, ver, 
                             logtime.Year, logtime.Month, logtime.Day,
                             logtime.Hour, logtime.Minute, logtime.Second,
                             host, appname, csc);

    endofs -= nxtofs;
    nxtofs +=  UnicodeSPrint(&full_log_msg[nxtofs], endofs , L" R-SAT-PWT-SFR-%03d %s ", 
                             sfrid, evtype);


    endofs -= nxtofs;
 

    va_start(args, format);
    nxtofs += UnicodeVSPrint(&full_log_msg[nxtofs] , endofs, format, args);
    va_end(args);



    //Print(L"Mesage buf length : %d  , size : %d\n", StrnLenS(full_log_msg,8192), StrnSizeS(full_log_msg,8192));

    wrlog = (CHAR8 *)full_log_msg;
    nxtofs = remove_all_space(wrlog,StrnSizeS(full_log_msg,8192));
    //SBC_mem_print_bin("Log", (UINT8 *)wrlog, nxtofs);
    Print(L"Full Log msg : %a \n", wrlog);
    _sbc_write_log_file(wrlog,strlen(wrlog));
    
    

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


