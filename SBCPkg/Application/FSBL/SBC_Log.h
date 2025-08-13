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

#if defined(_SBC_DEBUG_ON_)
#define dprint(fmt,...) \
    DEBUG((DEBUG_INFO, "(%a:%d) : "fmt"\n",__FUNCTION__, __LINE__,##__VA_ARGS__))

#define eprint(fmt,...) \
    DEBUG((DEBUG_ERROR, "(ERROR %a:%a:%d) : "fmt"\n",__FILE__,__FUNCTION__, __LINE__,##__VA_ARGS__))


#define intgreen_dprint(fmt,...) \
    Print(ANSI_COLOR_GREEN L"(%a:%d) : "fmt" \n"ANSI_COLOR_RESET,__FUNCTION__, __LINE__,##__VA_ARGS__)

#define int_dprint(fmt,...) \
    Print(L"(%a:%d) : "fmt" %a\n", __FUNCTION__, __LINE__,##__VA_ARGS__)

#define int_eprint(fmt,...) \
    Print(ANSI_COLOR_RED_BOLD L"(%a:%d) : "fmt" \n" ANSI_COLOR_RESET, __FUNCTION__, __LINE__,##__VA_ARGS__)
#else
#define dprint(fmt,...)
#define eprint(fmt,...)
#define intgreen_dprint(fmt,...)
#define int_dprint(fmt,...) 
#define int_eprint(fmt,...)
#endif

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
  IN  CONST CHAR8 *Format,
  ...
  );

UINTN SBC_LogFmtOut(OUT CHAR16 *outbuf, IN CONST CHAR16 *fmt, ...);
UINTN SBC_LogFmtOutNoraml(IN CONST CHAR16 *fmt, ...);
EFI_STATUS SBC_CustomPrint (
  IN CONST CHAR16 *Format,
  ...
  );


EFI_STATUS
EFIAPI
SBC_LogCustomPrint (
  OUT CHAR16 *OutFormat,
  IN CONST CHAR16 *Format,
  ...
  );

extern CHAR16 mrgmsg[8192]; 

CHAR16 *SBC_LogMrg(CONST CHAR16 *fmt, ...);

VOID  SBC_LogPrint(CONST CHAR16* func, UINT32 funcline, UINT32 prio, UINT32 ver, CHAR16 *host, 
                        CHAR16 *appname, CHAR16 *csc,
                        UINT32 sfrid, CHAR16 *evtype,
                        CHAR16 *format, ...);


#define sbc_err_sysprn(prio, ver, host, appname, csc, sfrid, evtype, fmt,...)                                  \
    SBC_LogPrint((CONST CHAR16 *)__FUNCTION__, (UINT32)__LINE__, prio, ver, host, appname, csc, sfrid, evtype, fmt, ##__VA_ARGS__)

typedef enum {
    LOG_LEVEL_DEBUG,    // 디버그 정보 (가장 상세)
    LOG_LEVEL_INFO,     // 일반 정보
    LOG_LEVEL_NOTICE,   // 일반적이지만 중요한 조건
    LOG_LEVEL_WARNING,  // 경고 조건
    LOG_LEVEL_ERROR,    // 에러 조건
    LOG_LEVEL_CRITICAL, // 치명적인 에러 (시스템 중단 가능성)
    LOG_LEVEL_ALERT,    // 즉시 조치가 필요한 조건
    LOG_LEVEL_EMERGENCY // 시스템 사용 불가 (가장 심각)
} LOG_LEVEL;

//
// 이벤트/카테고리 정의
// 로그 메시지가 어떤 종류의 이벤트에 속하는지 나타냅니다.
//
typedef enum {
    LOG_EVENT_GENERIC,      // 일반 이벤트
    LOG_EVENT_BOOT_INIT,    // 부팅 초기화
    LOG_EVENT_DRIVER_LOAD,  // 드라이버 로드
    LOG_EVENT_FS_OPERATION, // 파일 시스템 작업
    LOG_EVENT_NETWORK,      // 네트워크 관련
    LOG_EVENT_SECURITY,     // 보안 관련
    LOG_EVENT_CONFIG,       // 설정 관련
    LOG_EVENT_NVRAM,        // NVRAM 관련
    LOG_EVENT_REBOOT,       // 재부팅 관련
    // ... 필요한 이벤트 추가
} LOG_EVENT;

VOID UefiLog(LOG_LEVEL Level, LOG_EVENT Event, CONST CHAR16 *Format, ...);
#endif
