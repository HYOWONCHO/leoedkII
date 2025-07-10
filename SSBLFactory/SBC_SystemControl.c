//#include <Library/UefiBootServiceTableLib.h>
//#include <Library/UefiRuntimeServiceTableLib.h>

#include "SBC_SystemControl.h"



VOID SBC_RebootSystem(VOID)
{
  //Print(L"Rebooting ... \n");
  //gRT->ResetSystem(EfiResetCold, EFI_SUCCESS, 0, NULL);
  return;
}


VOID SBC_ShutdownSystem(VOID)
{
  //Print(L"Shutting down ... \n");
  //gRT->ResetSystem(EfiResetShutdown, EFI_SUCCESS, 0 NULL);
  return;
}
