#ifndef __SYSTEM_CONTROL_H
#define __SYSTEM_CONTROL_H
#include "SBC_ErrorType.h"


#pragma pack(1)

typedef struct _sw_whitelist_t {
    UINT8 name[256];
    UINT8 ver[256];
    UINTN offset;
}sw_whitels_t  ;

/**
 * @brief In case of Recovery boot mode, behavior to the secure
 *        boot
 * @var sb_rcv_proc_t::baseans          LV_t
 * @var sb_rcv_proc_t::handle           Block I/O behavior handle        
 * @author leonc (8/1/25)   
 */
typedef struct _sb_rcv_proc_t {
    VOID *migkey;
    VOID *osid;
    VOID *baseans;
    VOID *handle;
    VOID *whitels;          /*! Software List */
}sb_rcv_proc_t;


typedef struct _sw_node_t {
    UINT8 status;
    UINT8 pos;
    UINT8 sw0;
    UINT8 sw1;
    UINT8 reserved[12];
    off_t sw0_off;
    off_t sw1_off;
}sw_node_t;

#pragma pack()
VOID SBC_ShutdownSystem(VOID);
VOID SBC_RebootSystem(VOID);

SBCStatus  SBC_SecureBootCheck(VOID *priv);
#endif
