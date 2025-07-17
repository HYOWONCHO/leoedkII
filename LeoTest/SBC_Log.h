#ifndef __SBCLOG__
#define __SBCLOG__

#include <Library/DebugLib.h>

#ifndef ARG_UNUSED
#   define ARG_UNUSED   __attribute__ ((unused))
#endif

// ANSI escape code for red foreground, bold
#define ANSI_COLOR_RED_BOLD "\x1b[1;31m"
// ANSI escape code for green foreground
#define ANSI_COLOR_GREEN    "\x1b[32m"
// ANSI escape code to reset color and attributes
#define ANSI_COLOR_RESET    "\x1b[0m"

/*!
    \breif SBC System Log Priority 
 */
typedef enum {
    SBS_LOG_CMN_PRIO_ALERT              = 185,
    SBC_LOG_CMN_PRIO_CRIT,                          /// Critical
    SBC_LOG_CMN_PRIO_ERR,
    SBC_LOG_CMN_PRIO_WRN,                           /// Warning
    SBC_LOG_CMN_PRIO_NOTICE,
    SBC_LOG_CMN_PRIO_INFO,
    SBC_LOG_CMN_PRIO_DBG
}t_sbc_syslog_prio;

#define SBC_LOG_FSBL_APPNAME                        L"FSBL"
#define SBC_LOG_SSBL_APPNAME                        L"SSBL"

#define SBC_LOG_HOSTNAME                            L"N/A"

//#define LINE_LEN 16
void SBC_mem_print_bin(
        CHAR8 *title /**< [in] display name strings */,
        UINT8* buffer /**< [in] print buffer  */,
        UINT32 length /**< [in] length of buffer */
        );

void SBC_external_mem_print_bin(
        CHAR8 *title /**< [in] display name strings */,
        UINT8* buffer /**< [in] print buffer  */,
        UINT32 length /**< [in] length of buffer */
        );

VOID SBC_LogBoolean(BOOLEAN expression, CONST CHAR8 *funcname, UINTN linenumber, 
                    CONST CHAR8 *filename, CONST CHAR8 *description);


VOID SBC_LogMsg(CHAR8* logmsg, CONST CHAR8 *funcname, UINTN linenumber, 
                CONST CHAR8 *filename);

#define SBCLOGBOOLEAN(expression)    \
  SBC_LogBoolean((expression), __func__, __LINE__ , __FILE__, #expression)

#define SBCLOGMSG(logmsg) \
  SBC_LogMsg(#logmsg, __func__, __LINE__ , __FILE__)

#define dprint(fmt,...) \
    DEBUG((DEBUG_INFO, "(%a:%d) : "fmt"\n",__FUNCTION__, __LINE__,##__VA_ARGS__))

#define eprint(fmt,...) \
    DEBUG((DEBUG_ERROR, "(ERROR %a:%d) : "fmt"\n",__FUNCTION__, __LINE__,##__VA_ARGS__))


#define intgreen_dprint(fmt,...) \
    Print(ANSI_COLOR_GREEN L"(%a:%d) : "fmt" \n"ANSI_COLOR_RESET,__FUNCTION__, __LINE__,##__VA_ARGS__)

#define int_dprint(fmt,...) \
    Print(L"(%a:%d) : "fmt" %a\n", __FUNCTION__, __LINE__,##__VA_ARGS__)

#define int_eprint(fmt,...) \
    Print(ANSI_COLOR_RED_BOLD L"(%a:%d) : "fmt" \n" ANSI_COLOR_RESET, __FUNCTION__, __LINE__,##__VA_ARGS__)

/*
extern VOID  SBC_LogWrite(UINT32 prio, CHAR16 *ver, CHAR16 *host,                                                
                        CHAR16 *appname, CHAR16 *csc,                                                            
                        UINT32 sfrid, CHAR16 *evtype,                                                            
                        CONST CHAR16 *format, ...);                                                              
#define sbc_err_syslog(prio, ver, host, appname, csc, sfrid, evtype, fmt, ...)                                  \
    SBC_LogWrite(prio, ver, host, appnmae, csc, sfrid, evtype, fmt, ##__VA_ARGS__)                               
*/

UINTN
AsciiPrintToBuffer (
  IN  CONST CHAR16 *Format,
  ...
  );

VOID  SBC_LogPrint(CONST CHAR16* func, UINT32 funcline, UINT32 prio, UINT32 ver, CHAR16 *host, 
                        CHAR16 *appname, CHAR16 *csc,
                        UINT32 sfrid, CHAR16 *evtype,
                        CHAR16 *format, ...);

#define sbc_err_sysprn(prio, ver, host, appname, csc, sfrid, evtype, fmt,...)                                  \
    SBC_LogPrint((CONST CHAR16 *)__FUNCTION__, (UINT32)__LINE__, prio, ver, host, appname, csc, sfrid, evtype, fmt "\n", ##__VA_ARGS__)


#endif
