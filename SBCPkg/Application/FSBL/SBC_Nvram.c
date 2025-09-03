#include <Uefi.h>
#include <Library/UefiLib.h>
#include <Library/UefiBootServicesTableLib.h>
#include <Library/UefiRuntimeServicesTableLib.h>
#include <Library/MemoryAllocationLib.h>
#include <Guid/GlobalVariable.h>   // gEfiGlobalVariableGuid


STATIC EFI_GUID gSpImVendorGuid =
      { 0xd4fe1500, 0x6c3c, 0x4ad5,
      { 0x9e, 0xa1, 0x22, 0xd2, 0x97, 0x6c, 0x56, 0xd9 } };


EFI_STATUS SBC_NvramListAllVariables(VOID)
{
    EFI_STATUS Status;
    UINTN NameSize = 0;
    EFI_GUID VendorGuid;
    CHAR16 *Name = NULL;

    // First call: query required size
    Status = gRT->GetNextVariableName(&NameSize, NULL, &VendorGuid);
    if (Status != EFI_BUFFER_TOO_SMALL) return Status;

    Name = AllocatePool(NameSize);
    if (!Name) return EFI_OUT_OF_RESOURCES;

    Name[0] = L'\0';
    // Real first fetch
    Status = gRT->GetNextVariableName(&NameSize, Name, &VendorGuid);
    while (!EFI_ERROR(Status)) {
        Print(L"%g : %s\n", &VendorGuid, Name);

        // Reset NameSize to current buffer capacity each iteration
        NameSize = NameSize; // (unchanged capacity)
        Status = gRT->GetNextVariableName(&NameSize, Name, &VendorGuid);
        if (Status == EFI_BUFFER_TOO_SMALL) {
            // Grow buffer and retry
            FreePool(Name);
            Name = AllocatePool(NameSize);
            if (!Name) return EFI_OUT_OF_RESOURCES;
            Name[0] = L'\0';
            Status = gRT->GetNextVariableName(&NameSize, Name, &VendorGuid);
        }
    }

    if (Status == EFI_NOT_FOUND) Status = EFI_SUCCESS;
    if (Name) FreePool(Name);
    return Status;
}

EFI_STATUS SBC_NvramWriteVar(VOID *varname, VOID *payload, VOID *sz_pl)
{
    UINT32 Attr =
        EFI_VARIABLE_NON_VOLATILE;

    UINTN sz_payload = *(UINTN *)sz_data;

    return gRT->SetVariable(
        (CHAR16 *)varname,
        &gSpImVendorGuid,
        Attr,
        sz_pl,
        payload
    );
}

EFI_STATUS SBC_NvramReadVar(VOID *varname, VOID *payload, VOID *sz_pl)
{
    EFI_STATUS Status;
    UINT32 Attr = 0;
    UINTN sz_payload = *(UINTN *)sz_data;

    Status = gRT->GetVariable(
        (CAHR16 *)varname, 
        &gSpImVendorGuid,
        &Attr, 
        (UINTN *)sz_pl,
        payload);

    if (!EFI_ERROR(Status)) {
        Print(L"%s = %d, Attr=0x%08x \n", (CAHR16 *)varname, (UINTN)attr);
    }
    else {
        Print(L"GetVariable %s Failed %d\n", (CHAR16 *)varname, Status);
    }

    return EFI_SUCCESS;

}

