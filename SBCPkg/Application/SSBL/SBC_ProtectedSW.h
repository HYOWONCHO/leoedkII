#ifndef SBC_PROCTED_SW_H
#define SBC_PROCTED_SW_H

#include "SBC_ErrorType.h"
#include "SBC_TypeDefs.h"

typedef struct {
    CHAR8 name[256];
    CHAR8 ver[256];
    UINTN sw_node_off;
} sw_path_t;

typedef struct {
    UINT8 status;
    UINT8 pos;
    UINT8 sw0;
    UINT8 sw1;
    UINT8 reserved[12];
    UINTN sw0_off;
    UINTN sw1_off;
} sw_node_t;


/*!
 * \fn SBCStatus SBC_ProtSWGetCnt(VOID *handle, UINTN *cnt)
 * 
 * \brief 
 * 
 * \author leoc (9/25/25)
 * 
 * \param[in] handle Pointer to  Boot Proc Structure
 * \param[out] cnt   Number of count for Protected SW 
 * 
 * \return SBCStatus 
 */
SBCStatus SBC_ProtSWGetCnt(VOID *handle, UINTN *cnt);


#endif

