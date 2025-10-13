#include <Uefi.h>
#include <Library/UefiLib.h>
#include <Library/UefiBootServicesTableLib.h>
#include <Library/UefiRuntimeServicesTableLib.h>
#include <Library/MemoryAllocationLib.h>
#include <Library/BaseMemoryLib.h>
#include <Guid/GlobalVariable.h>   // gEfiGlobalVariableGuid


STATIC EFI_GUID gSpImVendorGuid =
      { 0xd4fe1500, 0x6c3c, 0x4ad5,
      { 0x9e, 0xa1, 0x22, 0xd2, 0x97, 0x6c, 0x56, 0xd9 } };



VOID SBC_NvramInit(VOID *priv)
{
    return;
}

VOID SBC_NvramDeInit(VOID *priv)
{
    return;
}


EFI_STATUS SBC_BiosReadBootOrder(VOID)
{
    EFI_STATUS Status;
    UINTN DataSize = 0;
    UINT16 *BootOrder = NULL;
    UINT32 Attributes = 0;

    // Probe size
    Status = gRT->GetVariable(L"BootOrder", &gEfiGlobalVariableGuid,
                              &Attributes, &DataSize, NULL);
    if (Status != EFI_BUFFER_TOO_SMALL) {
        return Status; // Not present or unexpected error
    }

    BootOrder = AllocatePool(DataSize);
    if (BootOrder == NULL) return EFI_OUT_OF_RESOURCES;

    Status = gRT->GetVariable(L"BootOrder", &gEfiGlobalVariableGuid,
                              &Attributes, &DataSize, BootOrder);
    if (!EFI_ERROR(Status)) {
        UINTN Count = DataSize / sizeof(UINT16);
        Print(L"BootOrder (%u entries):", (UINTN)Count);
        for (UINTN i = 0; i < Count; ++i) {
            Print(L" %04x", BootOrder[i]);
        }
        Print(L"\n");
    } else {
        Print(L"GetVariable BootOrder failed: %r\n", Status);
    }

    if (BootOrder) FreePool(BootOrder);
    return Status;
}

EFI_STATUS SBC_NvramListAllVariables(VOID)
{
    EFI_STATUS Status;
    UINTN NameSize = 0;
    EFI_GUID VendorGuid;
    CHAR16 *Name = NULL;

    Print(L"Non-voliate RAM List ....  \n");
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

EFI_STATUS SBC_NvramSetVar(VOID *varname, VOID *payload, VOID *sz_pl)
{
    UINTN var_len = *(UINTN *)sz_pl;

    Print(L"SetVar Name : %s, Var Size : %d \n", (CHAR16 *)varname, var_len);
    return gRT->SetVariable(
        (CHAR16 *)varname,                 // 변수 이름 (UTF-16)
        &gSpImVendorGuid,           // 벤더 GUID (네임스페이스 구분용)
        EFI_VARIABLE_NON_VOLATILE |
        EFI_VARIABLE_BOOTSERVICE_ACCESS |
        EFI_VARIABLE_RUNTIME_ACCESS,  // 속성
        var_len,            // 데이터 크기
        payload                     // 데이터
    );
}

EFI_STATUS SBC_NvramGetVar(VOID *varname, VOID *payload, VOID *sz_pl)
{
    EFI_STATUS Status;
    UINTN DataSize = 0;
    UINT32 Attributes;
    UINT8 *Buffer = NULL;

    [[maybe_unused]] UINTN var_len = *(UINTN *)sz_pl;

    //Print(L"GetVar Name : %s, Var Size : %d \n", (CHAR16 *)varname, var_len);
    Status = gRT->GetVariable((CHAR16 *)varname, &gSpImVendorGuid,
                              &Attributes, &DataSize, NULL);
    if (Status != EFI_BUFFER_TOO_SMALL) {
        Print(L"Nvram GetVar error %r \n", Status);
        return Status;  
    }

    // 2단계: 버퍼 할당 후 실제 읽기
    Buffer = AllocatePool(DataSize);
    if (!Buffer) return EFI_OUT_OF_RESOURCES;

    Status = gRT->GetVariable((CHAR16 *)varname, &gSpImVendorGuid,
                              &Attributes, &DataSize, Buffer);
    if (!EFI_ERROR(Status)) {
        Print(L"MyVar = ");
        for (UINTN i = 0; i < DataSize; i++) {
            Print(L"%02x ", Buffer[i]);
        }
        Print(L"\nAttr=0x%08x\n", Attributes);
    }

    CopyMem(payload, Buffer, DataSize);

    if (Buffer) FreePool(Buffer);
    return Status;

}

