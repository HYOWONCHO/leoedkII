#ifndef __SYSTEM_CONTROL_H
#define __SYSTEM_CONTROL_H
#include "SBC_ErrorType.h"
VOID SBC_ShutdownSystem(VOID);
VOID SBC_RebootSystem(VOID);

SBCStatus  SBC_SecureBootCheck(VOID *priv);
#endif
