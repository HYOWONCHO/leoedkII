#ifndef __SYSTEM_CONTROL_H
#define __SYSTEM_CONTROL_H
#include "SBC_ErrorType.h"


#pragma pack(1)

typedef struct _sw_whitelist_t {
    UINT8 name[256];
    UINT8 ver[256];
    UINTN offset;
}sw_white_list_t;

/**
 * @brief In case of Recovery boot mode, behavior to the secure
 *        boot
 * @var sb_rcv_proc_t::baseans       LV_t
 * @author leonc (8/1/25)
 */
typedef struct _sb_rcv_proc_t {
    VOID *osid;
    VOID *baseans;
    VOID *handle;

}sb_rcv_proc_t;

#pragma pack()
VOID SBC_ShutdownSystem(VOID);
VOID SBC_RebootSystem(VOID);

SBCStatus  SBC_SecureBootCheck(VOID *priv);
#endif
