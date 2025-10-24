#ifndef __SYSTEM_CONTROL_H
#define __SYSTEM_CONTROL_H

#include "SBC_ErrorType.h"

SBCStatus SBC_BootKeyModeChange(UINT32 newbm, UINT32 newkey, VOID *priv);

VOID SBC_ShutdownSystem(VOID);
VOID SBC_RebootSystem(VOID);


#endif
