#include <Uefi.h>
#include <Library/UefiRuntimeServicesTableLib.h>
#include <Library/BaseLib.h>
#include <Library/UefiLib.h>

#include "SBC_SystemControl.h"


VOID SBC_RebootSystem(VOID)
{
  Print(L"Reset SBC System ... \n");
  gRT->ResetSystem(EfiResetCold, EFI_SUCCESS, 0, NULL);
  return;
}


VOID SBC_ShutdownSystem(VOID)
{
  Print(L"Shutting down SBC System ... \n");
  gRT->ResetSystem(EfiResetShutdown, EFI_SUCCESS, 0, NULL);
  return;
}
