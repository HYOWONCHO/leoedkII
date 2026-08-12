#ifndef __SBCLOG__
#define __SBCLOG__

#include <Protocol/SimpleFileSystem.h>
#include <Library/DebugLib.h>
#include <Library/PrintLib.h>
#include <Library/UefiLib.h>

#include "SBC_Timer.h"

#ifndef ARG_UNUSED
#define ARG_UNUSED(x) ((void)(x))
#endif

#define FSBL_LOG_PATH              L"\\EFI\\BOOT\\sys_log_for_fsbl.log"

#define SYS_LOG_EVT_VALIDATION     L"Validation"
#define SYS_LOG_EVT_DETECTION      L"Detection"
#define SYS_LOG_HOST_BOOT          L"AT_BOOT"
#define SYS_LOG_APP_NAME           L"FSBL"
#define SYS_LOG_CSC_NAME           L"SAT"

#define SBC_LOG_FSBL_APPNAME       L"FSBL"
#define SBC_LOG_SSBL_APPNAME       SYS_LOG_APP_NAME
#define SBC_LOG_HOSTNAME           L"N/A"

#define BYTES_PER_LINE             16

#define SBC_LOG_DEFAULT_BUF_SIZE   (16 * 1024)

/*
 * ANSI Color Codes for DEBUG().
 * DEBUG() format string must be CHAR8.
 */
#define SBC_C_RST                  "\x1b[0m"
#define SBC_C_RED                  "\x1b[31m"
#define SBC_C_GRN                  "\x1b[32m"
#define SBC_C_YEL                  "\x1b[33m"
#define SBC_C_BLU                  "\x1b[34m"

/*
 * ANSI Color Codes for Print().
 * Print() format string must be CHAR16.
 */
#define SBC_UC_RST                 L"\033[0m"
#define SBC_UC_RED_BOLD            L"\033[1;31m"
#define SBC_UC_GRN                 L"\033[32m"

typedef enum {
    SBC_LOG_CMN_PRIO_ALERT = 185,
    SBC_LOG_CMN_PRIO_CRIT,
    SBC_LOG_CMN_PRIO_ERR,
    SBC_LOG_CMN_PRIO_WRN,
    SBC_LOG_CMN_PRIO_NOTICE,
    SBC_LOG_CMN_PRIO_INFO,
    SBC_LOG_CMN_PRIO_DBG
} t_sbc_syslog_prio;

typedef enum {
    LOG_LEVEL_DEBUG,
    LOG_LEVEL_INFO,
    LOG_LEVEL_NOTICE,
    LOG_LEVEL_WARNING,
    LOG_LEVEL_ERROR,
    LOG_LEVEL_CRITICAL,
    LOG_LEVEL_ALERT,
    LOG_LEVEL_EMERGENCY
} LOG_LEVEL;

typedef enum {
    LOG_EVENT_GENERIC,
    LOG_EVENT_BOOT_INIT,
    LOG_EVENT_DRIVER_LOAD,
    LOG_EVENT_FS_OPERATION,
    LOG_EVENT_NETWORK,
    LOG_EVENT_SECURITY,
    LOG_EVENT_CONFIG,
    LOG_EVENT_NVRAM,
    LOG_EVENT_REBOOT
} LOG_EVENT;

typedef struct {
    EFI_HANDLE                       FsHandle;
    EFI_SIMPLE_FILE_SYSTEM_PROTOCOL *SimpleFs;
    EFI_FILE_PROTOCOL               *Root;
    EFI_FILE_PROTOCOL               *File;

    CHAR16                          *FilePath;

    CHAR8                           *Buf;
    UINTN                            BufCap;
    UINTN                            BufLen;

    BOOLEAN                          Ready;
} SBC_LOG_CTX;

extern SBC_LOG_CTX gLogCtx;
extern CHAR16      mrgmsg[8192];

/* -------------------------------------------------------------------------- */
/* DEBUG print macros                                                          */
/* -------------------------------------------------------------------------- */

#ifdef _DEBUG_PRINT_ON_
#ifdef _RUN_GCS_
        #define SBCLOGBOOLEAN(expression)                                      \
    do {                                                               \
        SBC_LogBoolean(                                                \
            (expression),                                              \
            __func__,                                                  \
            __LINE__,                                                  \
            __FILE__,                                                  \
            #expression                                                \
        );                                                             \
    } while (0)

        #define SBCLOGMSG(logmsg)                                              \
    do {                                                               \
        SBC_LogMsg(                                                    \
            #logmsg,                                                   \
            __func__,                                                  \
            __LINE__,                                                  \
            __FILE__                                                   \
        );                                                             \
    } while (0)

        #define iprint(fmt, ...)                                               \
    do {                                                               \
        DEBUG((                                                        \
            DEBUG_INFO,                                                \
             "[INFO]"  " GCS " fmt "\n",        \
            ##__VA_ARGS__                                              \
        ));                                                            \
    } while (0)

        #define wprint(fmt, ...)                                               \
    do {                                                               \
        DEBUG((                                                        \
            DEBUG_WARN,                                                \
             "[WARN]"  " GCS " fmt "\n",        \
            ##__VA_ARGS__                                              \
        ));                                                            \
    } while (0)

        #define eprint(fmt, ...)                                               \
    do {                                                               \
        DEBUG((                                                        \
            DEBUG_ERROR,                                               \
             "[ERROR]"  " GCS " fmt "\n",       \
            ##__VA_ARGS__                                              \
        ));                                                            \
    } while (0)


        #define dprint(fmt, ...)                                               \
    do {                                                               \
        DEBUG((                                                        \
            DEBUG_INFO,                                                \
             "[DEBUG]"  " GCS " fmt "\n",       \
            ##__VA_ARGS__                                              \
        ));                                                            \
    } while (0)


        #define intgreen_dprint(fmt, ...)                                      \
    do {                                                               \
        Print(                                                         \
             L"GCS : " fmt L"\n" SBC_UC_RST,            \
            ##__VA_ARGS__                                              \
        );                                                             \
    } while (0)

        #define int_dprint(fmt, ...)                                           \
    do {                                                               \
        Print(                                                         \
            L"GCS : " fmt L"\n",                                  \
            ##__VA_ARGS__                                              \
        );                                                             \
    } while (0)

        #define int_eprint(fmt, ...)                                           \
    do {                                                               \
        Print(                                                         \
             L"GCS : " fmt L"\n" SBC_UC_RST,       \
            ##__VA_ARGS__                                              \
        );                                                             \
    } while (0)
#else
#define SBCLOGBOOLEAN(expression)                                      \
    do {                                                               \
        SBC_LogBoolean(                                                \
            (expression),                                              \
            __func__,                                                  \
            __LINE__,                                                  \
            __FILE__,                                                  \
            #expression                                                \
        );                                                             \
    } while (0)

#define SBCLOGMSG(logmsg)                                              \
    do {                                                               \
        SBC_LogMsg(                                                    \
            #logmsg,                                                   \
            __func__,                                                  \
            __LINE__,                                                  \
            __FILE__                                                   \
        );                                                             \
    } while (0)

#define iprint(fmt, ...)                                               \
    do {                                                               \
        DEBUG((                                                        \
            DEBUG_INFO,                                                \
             "[INFO]"  " (%a:%d) " fmt "\n",        \
            __func__,                                                  \
            __LINE__,                                                  \
            ##__VA_ARGS__                                              \
        ));                                                            \
    } while (0)

#define wprint(fmt, ...)                                               \
    do {                                                               \
        DEBUG((                                                        \
            DEBUG_WARN,                                                \
             "[WARN]"  " (%a:%d) " fmt "\n",        \
            __func__,                                                  \
            __LINE__,                                                  \
            ##__VA_ARGS__                                              \
        ));                                                            \
    } while (0)

#define eprint(fmt, ...)                                               \
    do {                                                               \
        DEBUG((                                                        \
            DEBUG_ERROR,                                               \
             "[ERROR]"  " (%a:%d) " fmt "\n",       \
            __func__,                                                  \
            __LINE__,                                                  \
            ##__VA_ARGS__                                              \
        ));                                                            \
    } while (0)


#define dprint(fmt, ...)                                               \
    do {                                                               \
        DEBUG((                                                        \
            DEBUG_INFO,                                                \
             "[DEBUG]"  " (%a:%d) " fmt "\n",       \
            __func__,                                                  \
            __LINE__,                                                  \
            ##__VA_ARGS__                                              \
        ));                                                            \
    } while (0)


#define intgreen_dprint(fmt, ...)                                      \
    do {                                                               \
        Print(                                                         \
             L"(%a:%d) : " fmt L"\n" SBC_UC_RST,            \
            __func__,                                                  \
            __LINE__,                                                  \
            ##__VA_ARGS__                                              \
        );                                                             \
    } while (0)

#define int_dprint(fmt, ...)                                           \
    do {                                                               \
        Print(                                                         \
            L"(%a:%d) : " fmt L"\n",                                  \
            __func__,                                                  \
            __LINE__,                                                  \
            ##__VA_ARGS__                                              \
        );                                                             \
    } while (0)

#define int_eprint(fmt, ...)                                           \
    do {                                                               \
        Print(                                                         \
             L"(%a:%d) : " fmt L"\n" SBC_UC_RST,       \
            __func__,                                                  \
            __LINE__,                                                  \
            ##__VA_ARGS__                                              \
        );                                                             \
    } while (0)
#endif
#else  /* !_DEBUG_PRINT_ON_ */

#define SBCLOGBOOLEAN(expression)                                      \
    do {                                                               \
        ARG_UNUSED(expression);                                        \
    } while (0)

#define SBCLOGMSG(logmsg)                                              \
    do {                                                               \
        ARG_UNUSED(logmsg);                                            \
    } while (0)

#define iprint(fmt, ...)             do { } while (0)
#define wprint(fmt, ...)             do { } while (0)
#define eprint(fmt, ...)             do { } while (0)
#define dprint(fmt, ...)             do { } while (0)
#define intgreen_dprint(fmt, ...)    do { } while (0)
#define int_dprint(fmt, ...)         do { } while (0)
#define int_eprint(fmt, ...)         do { } while (0)

#endif /* _DEBUG_PRINT_ON_ */

#ifdef _SHELL_CMD_LINE_

#define cmd_dprint(fmt, ...)                                           \
    do {                                                               \
        DEBUG((                                                        \
            DEBUG_INFO,                                                \
            "(%a:%d) : " fmt "\n",                                    \
            __func__,                                                  \
            __LINE__,                                                  \
            ##__VA_ARGS__                                              \
        ));                                                            \
    } while (0)

#define cmd_eprint(fmt, ...)                                           \
    do {                                                               \
        DEBUG((                                                        \
            DEBUG_ERROR,                                               \
            "(ERROR %a:%a:%d) : " fmt "\n",                          \
            __FILE__,                                                  \
            __func__,                                                  \
            __LINE__,                                                  \
            ##__VA_ARGS__                                              \
        ));                                                            \
    } while (0)

#else

#define cmd_dprint(fmt, ...)         do { } while (0)
#define cmd_eprint(fmt, ...)         do { } while (0)

#endif /* _SHELL_CMD_LINE_ */

#ifdef _USECASE_TEST_

#define _ucprint(fmt, ...)                                             \
    do {                                                               \
        DEBUG((                                                        \
            DEBUG_INFO,                                                \
            "(%a:%d) : " fmt "\n",                                    \
            __func__,                                                  \
            __LINE__,                                                  \
            ##__VA_ARGS__                                              \
        ));                                                            \
    } while (0)

VOID
_uc_mem_print_bin(
    IN CHAR8  *Title,
    IN UINT8  *Buffer,
    IN UINT32  Length
);

#else

#define _ucprint(fmt, ...)           do { } while (0)

#endif /* _USECASE_TEST_ */

/* -------------------------------------------------------------------------- */
/* Function declarations                                                       */
/* -------------------------------------------------------------------------- */

VOID
SBC_mem_print_bin(
    IN CHAR8  *Title,
    IN UINT8  *Buffer,
    IN UINT32  Length
);

VOID
SBC_external_mem_print_bin(
    IN CHAR8  *Title,
    IN UINT8  *Buffer,
    IN UINT32  Length
);

VOID
SBC_LogBoolean(
    IN BOOLEAN     Expression,
    IN CONST CHAR8 *FuncName,
    IN UINTN       LineNumber,
    IN CONST CHAR8 *FileName,
    IN CONST CHAR8 *Description
);

VOID
SBC_LogMsg(
    IN CHAR8       *LogMsg,
    IN CONST CHAR8 *FuncName,
    IN UINTN       LineNumber,
    IN CONST CHAR8 *FileName
);

UINTN
AsciiPrintToBuffer(
    IN CONST CHAR8 *Format,
    ...
);

UINTN
SBC_LogFmtOut(
    OUT CHAR16       *OutBuf,
    IN  CONST CHAR16 *Fmt,
    ...
);

UINTN
SBC_LogFmtOutNoraml(
    IN CONST CHAR16 *Fmt,
    ...
);

EFI_STATUS
SBC_CustomPrint(
    IN CONST CHAR16 *Format,
    ...
);

CHAR16 *
SBC_LogMrg(
    IN CONST CHAR16 *Fmt,
    ...
);

VOID
SBC_LogPrint(
    IN CONST CHAR16 *Func,
    IN UINT32        FuncLine,
    IN UINT32        Prio,
    IN UINT32        Ver,
    IN CHAR16       *Host,
    IN CHAR16       *AppName,
    IN CHAR16       *Csc,
    IN UINT32        SfrId,
    IN CHAR16       *EvType,
    IN CHAR16       *Format,
    ...
);

EFI_STATUS
SBC_BuildHexFormattedMessage(
    IN  CONST VOID   *PubKey,
    IN  UINTN         PubKeySize,
    IN  CONST CHAR16 *FormatString,
    OUT CHAR16       *OutMsg,
    IN  UINTN         OutMsgBytes
);

UINTN
SBC_LogHexToStrChar8(
    IN  UINT8   *Data,
    IN  UINTN    Len,
    OUT CHAR8   *Out,
    IN  UINTN    OutCap,
    IN  BOOLEAN  Lowercase,
    IN  CHAR8    Sep
);

UINTN
SBC_LogHexToStrChar16(
    IN  UINT8   *Data,
    IN  UINTN    Len,
    OUT CHAR16  *Out,
    IN  UINTN    OutCap,
    IN  BOOLEAN  Lowercase,
    IN  CHAR16   Sep
);

VOID
SBC_LogHexKeyConvToChar16(
    OUT VOID *Out,
    IN  VOID *MsgBuf,
    IN  VOID *KeyMsg
);

EFI_STATUS
SBC_LogInit(
    OUT SBC_LOG_CTX  *Ctx,
    IN  EFI_HANDLE    FsHandle,
    IN  CONST CHAR16 *LogPath,
    IN  UINTN         BufferSize
);

EFI_STATUS
SBC_LogWrite16(
    IN OUT SBC_LOG_CTX  *Ctx,
    IN     CONST CHAR16 *Msg
);

EFI_STATUS
SBC_LogFlush(
    IN OUT SBC_LOG_CTX *Ctx
);

VOID
SBC_LogDeinit(
    IN OUT SBC_LOG_CTX *Ctx
);

EFI_STATUS
SBC_LogInitAuto(
    OUT SBC_LOG_CTX  *Ctx,
    IN  EFI_HANDLE    ImageHandle,
    IN  CONST CHAR16 *LogPath,
    IN  UINTN         BufferSize,
    OUT EFI_HANDLE   *OutFsHandle OPTIONAL
);

VOID
UefiLog(
    IN LOG_LEVEL     Level,
    IN LOG_EVENT     Event,
    IN CONST CHAR16 *Format,
    ...
);

VOID
SBC_LogElapsedTime(
    IN CONST CHAR16 *Tag,
    IN UINTN         Ns
);

#define sbc_err_sysprn(prio, ver, host, appname, csc, sfrid, evtype, fmt, ...) \
    SBC_LogPrint(                                                             \
        (CONST CHAR16 *)__FUNCTION__,                                         \
        (UINT32)__LINE__,                                                     \
        (prio),                                                               \
        (ver),                                                                \
        (host),                                                               \
        (appname),                                                            \
        (csc),                                                                \
        (sfrid),                                                              \
        (evtype),                                                             \
        (fmt),                                                                \
        ##__VA_ARGS__                                                         \
    )

#endif /* __SBCLOG__ */
