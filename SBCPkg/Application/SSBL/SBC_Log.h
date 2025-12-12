/********************************************************************************
 * Copyright (C) 2024 by Security Platform Inc.                                 *
 * This file is part of the SBC Project.                                        *
 *                                                                              *
 * This software contains confidential and proprietary information of           *
 * Security Platform Inc. Unauthorized reproduction, distribution, or           *
 * disclosure of this software, in whole or in part, is strictly prohibited.    *
 ********************************************************************************/

#ifndef __SBCLOG__
#define __SBCLOG__

#include <Library/DebugLib.h>

#include "SBC_Timer.h"

#ifndef ARG_UNUSED
#   define ARG_UNUSED   __attribute__ ((unused))
#endif

// ANSI escape code for red foreground, bold
#define ANSI_COLOR_RED_BOLD "\x1b[1;31m"
// ANSI escape code for green foreground
#define ANSI_COLOR_GREEN    "\x1b[32m"
// ANSI escape code to reset color and attributes
#define ANSI_COLOR_RESET    "\x1b[0m"

#define C_RST  "\033[0m"
#define C_RED  "\033[31m"
#define C_GRN  "\033[32m"
#define C_YEL  "\033[33m"
#define C_BLU  "\033[34m"
#define C_CYN  "\033[36m"


#define SYS_LOG_EVT_VALDIATION                  L"Validation"
#define SYS_LOG_EVT_DETECTION                   L"Detection"
#define SYS_LOG_HOST_BOOT                       L"AT_BOOT"
#define SYS_LOG_APP_NAME                        L"SSBL"
#define SYS_LOG_CSC_NAME                        L"SAT"
#define SSBL_LOG_PATH                           L"\\EFI\\BOOT\\sys_log_for_ssbl.log"
/**
 * @enum t_sbc_syslog_prio
 * @brief Defines priority levels for system logging messages.
 *
 * @var SBS_LOG_CMN_PRIO_ALERT
 *      Priority level for alert conditions. Requires immediate attention. (Value: 185)
 *
 * @var SBC_LOG_CMN_PRIO_CRIT
 *      Critical conditions. Indicates serious failures or system instability.
 *
 * @var SBC_LOG_CMN_PRIO_ERR
 *      Error conditions. Used for recoverable errors or failed operations.
 *
 * @var SBC_LOG_CMN_PRIO_WRN
 *      Warning conditions. Indicates potential issues that may require attention.
 *
 * @var SBC_LOG_CMN_PRIO_NOTICE
 *      Normal but significant events. Used for informational notices.
 *
 * @var SBC_LOG_CMN_PRIO_INFO
 *      Informational messages. General runtime information.
 *
 * @var SBC_LOG_CMN_PRIO_DBG
 *      Debug-level messages. Used for detailed internal diagnostics.
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
#define SBC_LOG_SSBL_APPNAME                        SYS_LOG_APP_NAME

#define SBC_LOG_HOSTNAME                            L"N/A"

//#define LINE_LEN 16

/**
 * @fn void SBC_mem_print_bin(CHAR8 *title, UINT8 *buffer, UINT32 length)
 * @brief Print binary data in hexadecimal format for debugging.
 */
void SBC_mem_print_bin(
    CHAR8 *title,   /**< [in] Display title string */
    UINT8 *buffer,  /**< [in] Pointer to data buffer */
    UINT32 length   /**< [in] Number of bytes to print */
);

/**
 * @fn void SBC_external_mem_print_bin(CHAR8 *title,
 *     UINT8 *buffer, UINT32 length)
 * @brief Print binary data in hexadecimal format for debugging.
 */
void SBC_external_mem_print_bin(
        CHAR8 *title /**< [in] display name strings */,
        UINT8* buffer /**< [in] print buffer  */,
        UINT32 length /**< [in] length of buffer */
        );

VOID SBC_LogBoolean(BOOLEAN expression, CONST CHAR8 *funcname, UINTN linenumber, 
                    CONST CHAR8 *filename, CONST CHAR8 *description);


VOID SBC_LogMsg(CHAR8* logmsg, CONST CHAR8 *funcname, UINTN linenumber, 
                CONST CHAR8 *filename);

#ifdef _DEBUG_PRINT_ON_
#define SBCLOGBOOLEAN(expression)    \
  SBC_LogBoolean((expression), __func__, __LINE__ , __FILE__, #expression)

#define SBCLOGMSG(logmsg) \
  SBC_LogMsg(#logmsg, __func__, __LINE__ , __FILE__)

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
//#error "Use Case test"
#define SBCLOGBOOLEAN(expression)    

#define SBCLOGMSG(logmsg) 

#define dprint(fmt,...) 

#define eprint(fmt,...) 

#define intgreen_dprint(fmt,...) 

#define int_dprint(fmt,...) 

#define int_eprint(fmt,...) 
#endif

#ifdef _USECASE_TEST_
#define _ucprint(fmt,...) \
    DEBUG((DEBUG_INFO, "(%a:%d) : "fmt"\n",__FUNCTION__, __LINE__,##__VA_ARGS__))

void _uc_mem_print_bin(
        CHAR8 *title /**< [in] display name strings */,
        UINT8* buffer /**< [in] print buffer  */,
        UINT32 length /**< [in] length of buffer */
        );
#else
#define _ucprint(fmt,...) 
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

//CHAR16 *SBC_LogMrg(CONST CHAR16 *fmt, ...);

/**
 * @fn VOID SBC_LogPrint(
 *       CONST CHAR16* func,
 *       UINT32 funcline,
 *       UINT32 prio,
 *       UINT32 ver,
 *       CHAR16 *host,
 *       CHAR16 *appname,
 *       CHAR16 *csc,
 *       UINT32 sfrid,
 *       CHAR16 *evtype,
 *       CHAR16 *format,
 *       ...)
 * @brief Print a formatted log message with metadata and variable arguments.
 *
 * @param[in] func       Name of the function where the log is generated (Unicode string).
 * @param[in] funcline   Source code line number where the log was called.
 * @param[in] prio       Log priority or severity level (e.g., DEBUG, INFO, WARN, ERROR).
 * @param[in] ver        Log version or protocol version identifier.
 * @param[in] host       Host or system identifier (Unicode string).
 * @param[in] appname    Application or module name (Unicode string).
 * @param[in] csc        Customer or component identifier (Unicode string).
 * @param[in] sfrid      SFR (Software Fault Record) or event identifier.
 * @param[in] evtype     Event type (e.g., "BOOT", "SECURE", "RUNTIME").
 * @param[in] format     Format string for variable arguments (Unicode string).
 * @param[in] ...        Variable arguments for printf-style formatting.
 *
 * @retval None
 */
VOID SBC_LogPrint(
    CONST CHAR16 *func,   /**< [in] Function name string */
    UINT32 funcline,      /**< [in] Line number of the log call */
    UINT32 prio,          /**< [in] Log priority (DEBUG, INFO, WARN, ERROR, etc.) */
    UINT32 ver,           /**< [in] Log version or schema ID */
    CHAR16 *host,         /**< [in] Host or system identifier */
    CHAR16 *appname,      /**< [in] Application or module name */
    CHAR16 *csc,          /**< [in] Customer or component code */
    UINT32 sfrid,         /**< [in] Software Fault Record (SFR) or event ID */
    CHAR16 *evtype,       /**< [in] Event type string (e.g., L"BOOT") */
    CHAR16 *format,       /**< [in] Format string for variable arguments */
    ...
);


/**
 * @fn EFI_STATUS SBC_BuildHexFormattedMessage(
 *       IN  CONST VOID  *PubKey,
 *       IN  UINTN        PubKeySize,
 *       IN  CONST CHAR16 *FormatString,
 *       OUT CHAR16      *OutMsg,
 *       IN  UINTN        OutMsgBytes)
 * @brief Build a formatted Unicode message containing a hexadecimal representation of binary data.
 *
 * Example usage:
 * @code
 * CHAR16 Msg[256];
 * SBC_BuildHexFormattedMessage(KeyData, KeyLen, L"Public Key: %s", Msg, sizeof(Msg));
 * @endcode
 *
 * The resulting message will contain the prefix text defined by the format string,
 * followed by the converted hexadecimal string of @p PubKey.
 *
 * @param[in]  PubKey        Pointer to the binary data (e.g., public key or hash) to be converted.
 * @param[in]  PubKeySize    Size of the binary data buffer in bytes.
 * @param[in]  FormatString  Unicode (CHAR16) format string that defines how the final
 *                           message should be constructed.
 *                           Example: `L"Key Digest: %s"`.
 * @param[out] OutMsg        Pointer to a caller-allocated buffer that receives the formatted message.
 *                           The buffer must be large enough to store the formatted text
 *                           and the hexadecimal string.
 * @param[in]  OutMsgBytes   Size of the output buffer @p OutMsg, in bytes.
 *
 * @retval EFI_SUCCESS           The formatted message was successfully created.
 * @retval EFI_INVALID_PARAMETER One or more parameters are NULL or invalid.
 * @retval EFI_BUFFER_TOO_SMALL  The output buffer is too small for the generated message.
 * @retval EFI_OUT_OF_RESOURCES  Memory allocation or internal buffer operation failed.
 */
EFI_STATUS SBC_BuildHexFormattedMessage(
    IN  CONST VOID  *PubKey,
    IN  UINTN        PubKeySize,
    IN  CONST CHAR16 *FormatString,
    OUT CHAR16      *OutMsg,
    IN  UINTN        OutMsgBytes
);



/*!
 * 
 * 
 * \author leoc (9/25/25)
 * 
 * \param data      Pointer to input byte array
 * \param len       Length of Data
 * \param out       Pointer to output byte array
 * \param out_cap   Lengthh of output element 
 * \param loweracse Specify the Upper and Lower case 
 * \param sep       Specify the delimiter 
 * 
 * \return UINTN    Actual recorded CHAR8 length excluding NULL character, On failure, return the 0 
 */
UINTN SBC_LogHexToStrChar8( UINT8 *data, UINTN len, CHAR8 *out, UINTN out_cap, BOOLEAN loweracse, CHAR8 sep);

/*!
 * 
 * 
 * \author leoc (9/25/25)
 * 
 * \param data      Pointer to input byte array
 * \param len       Length of Data
 * \param out       Pointer to output byte array
 * \param out_cap   Lengthh of output element 
 * \param loweracse Specify the Upper and Lower case 
 * \param sep       Specify the delimiter 
 * 
 * \return UINTN    Actual recorded CHAR16 length excluding NULL character, On failure, return the 0 
 */
UINTN SBC_LogHexToStrChar16( UINT8 *data, UINTN len, CHAR16 *out, UINTN out_cap, BOOLEAN loweracse, CHAR16 sep);

VOID SBC_LogHexKeyConvToChar16(VOID *out, VOID *msgbuf, VOID *keymsg);

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

/**
 * @fn SBC_LogElapsedTime
 * @brief Logs the elapsed time associated with a specific tag.
 *
 * @param[in] Tag  A null-terminated UTF-16 string representing the label or identifier for the timing event.
 * @param[in] Ns   Elapsed time in nanoseconds to be logged.
 */
VOID SBC_LogElapsedTime(const CHAR16 *Tag, UINTN Ns);
#endif

