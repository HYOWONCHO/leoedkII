#include <Uefi.h>
#include <Library/UefiLib.h>
#include <Library/DebugLib.h>



EFI_STATUS 
EFIAPI
UefiMain(
    IN EFI_HANDLE           ImageHandle,
    IN EFI_SYSTEM_TABLE     *SystemTablek
    )
{
    EFI_STATUS retval = EFI_SUCCESS;
    Print(L"FSBL Starting !!! \n");

    return retval;

}

