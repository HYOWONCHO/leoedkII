#include <Library/BaseMemoryLib.h>
#include <Library/MemoryAllocationLib.h>
#include <Library/BaseLib.h>
#include <Protocol/Smbios.h> // System Management BIOS header
#include <Uefi.h>
#include <Library/PcdLib.h>
#include <Library/UefiLib.h>
#include <Library/UefiBootServicesTableLib.h>
#include <Protocol/Smbios.h>
#include <Library/BaseLib.h>


// NVME parsing 
#include <Ppi/NvmExpressPassThru.h>
#include <IndustryStandard/Nvme.h>
#include <Guid/FileInfo.h>
#include <Protocol/DevicePathToText.h>
#include <Protocol/LoadedImage.h>

#include "SBC_CryptAES.h"
#include "SBC_TypeDefs.h"

#include "SBC_Util.h"
#include "SBC_Config.h"
#include "SBC_FileCtrl.h"

#include "SBC_Hashing.h"
#include "SBC_AntiTampering.h"
#include "SBC_EccSignVerify.h"



#pragma pack(1)
typedef struct {
    UINT8   Reserved[4];
    CHAR8   SerialNumber[20];
    // The rest of the 4096-byte structure is not used in this example.
} NVME_CONTROLLER_DATA;
#pragma pack()

static SBCStatus _kernel_image_load(EFI_HANDLE ImageHandle, LV_t *lv)
{
  SBCStatus                       ret = SBCFAIL;
  EFI_STATUS                      Status;
  EFI_SIMPLE_FILE_SYSTEM_PROTOCOL *SimpleFileSystem;
  EFI_FILE_PROTOCOL               *Root;
  EFI_FILE_PROTOCOL               *FileHandle;
  UINTN                           BufferSize;
  VOID                            *Buffer;
  EFI_DEVICE_PATH_PROTOCOL        *DevicePath;
  EFI_LOADED_IMAGE_PROTOCOL       *LoadedImage;
  EFI_HANDLE                      *HandleBuffer;
  UINTN                           NumberOfHandles;
  UINTN                           Index;
  CHAR16                          FilePath[] = L"\\EFI\\rocky\\vmlinuz_test"; // Path relative to the root of the file system
  BOOLEAN                         FoundFs1 = FALSE;
  EFI_DEVICE_PATH_TO_TEXT_PROTOCOL *DevicePathToText = NULL;
  CHAR16                          *DevicePathStr = NULL;
  CONST CHAR16                     *deviceidnetiifer = L"NVMe";


  // 1. Get the Loaded Image Protocol to determine the current device
  //    This is one way to find the file system where your current image is located.
  //    You could also iterate all SimpleFileSystem protocols to find FS1 explicitly.
  Status = gBS->OpenProtocol (
                  ImageHandle,
                  &gEfiLoadedImageProtocolGuid,
                  (VOID **)&LoadedImage,
                  ImageHandle,
                  NULL,
                  EFI_OPEN_PROTOCOL_GET_PROTOCOL
                  );
  if (EFI_ERROR (Status)) {
    Print(L"Failed to open LoadedImageProtocol: %r\n", Status);
    goto errdone;
  }

  // 2. Locate all Simple File System Protocols
  Status = gBS->LocateHandleBuffer (
                  ByProtocol,
                  &gEfiSimpleFileSystemProtocolGuid,
                  NULL,
                  &NumberOfHandles,
                  &HandleBuffer
                  );
  if (EFI_ERROR (Status)) {
    Print(L"Failed to locate SimpleFileSystemProtocol handles: %r\n", Status);
    goto errdone;
  }

  Print(L"Number of HandleBuffre : %d \n", NumberOfHandles);

  for (Index = 0; Index < NumberOfHandles; Index++) {
    Status = gBS->OpenProtocol (
                    HandleBuffer[Index],
                    &gEfiSimpleFileSystemProtocolGuid,
                    (VOID **)&SimpleFileSystem,
                    ImageHandle,
                    NULL,
                    EFI_OPEN_PROTOCOL_GET_PROTOCOL
                    );
    if (EFI_ERROR (Status)) {
      continue; // Skip if we can't open this instance
    }

    gBS->HandleProtocol(HandleBuffer[Index], &gEfiDevicePathProtocolGuid, (VOID**)&DevicePath);
    gBS->LocateProtocol(&gEfiDevicePathToTextProtocolGuid, NULL, (VOID**)&DevicePathToText);
    DevicePathStr = DevicePathToText->ConvertDevicePathToText(DevicePath, FALSE, FALSE);

    Print(L"Device path str : %s \n", DevicePathStr);
    if (StrStr((CONST CHAR16 *)DevicePathStr, deviceidnetiifer) == NULL) {
      Print(L"NVMe path NOT find \n");
      continue;
    }

    Status = SimpleFileSystem->OpenVolume (SimpleFileSystem, &Root);
    if (EFI_ERROR (Status)) {
      Print(L"Failed to open volume: %r\n", Status);
      continue;
    }

    FoundFs1 = TRUE; // Assuming we found the correct file system
    Print(L"Found a file system, attempting to open: %s\n", FilePath);
    break; // Found the file system, exit loop
  }

  gBS->FreePool(HandleBuffer);

  if (!FoundFs1) {
    Print(L"Could not locate the desired file system (FS1:).\n");
    ret = SBCNOTFND;
    goto errdone;
  }

  // 3. Open the X64.efi file
  Status = Root->Open (
                    Root,
                    &FileHandle,
                    FilePath,
                    EFI_FILE_MODE_READ,
                    0 // Attributes: no special attributes for reading
                    );
  if (EFI_ERROR (Status)) {
    Print(L"Failed to open file %s: %r\n", FilePath, Status);
    Root->Close(Root);
    goto errdone;
  }

  // 4. Get the file size
  EFI_FILE_INFO *FileInfo;
  BufferSize = 0;
  // First call to GetInfo with BufferSize = 0 to get the required buffer size
  Status = FileHandle->GetInfo (
                         FileHandle,
                         &gEfiFileInfoGuid,
                         &BufferSize,
                         NULL
                         );
  if (Status != EFI_BUFFER_TOO_SMALL) {
    Print(L"Failed to get file info (first call): %r\n", Status);
    FileHandle->Close(FileHandle);
    Root->Close(Root);
    goto errdone;
  }

  Status = gBS->AllocatePool (EfiBootServicesData, BufferSize, (VOID **)&FileInfo);
  if (EFI_ERROR (Status)) {
    Print(L"Failed to allocate memory for file info: %r\n", Status);
    FileHandle->Close(FileHandle);
    Root->Close(Root);
    goto errdone;
  }

  Status = FileHandle->GetInfo (
                         FileHandle,
                         &gEfiFileInfoGuid,
                         &BufferSize,
                         FileInfo
                         );
  if (EFI_ERROR (Status)) {
    Print(L"Failed to get file info (second call): %r\n", Status);
    gBS->FreePool(FileInfo);
    FileHandle->Close(FileHandle);
    Root->Close(Root);
    goto errdone;
  }

  UINT64 FileSize = FileInfo->FileSize;
  Print(L"File size of %s: %llu bytes\n", FilePath, FileSize);
  gBS->FreePool(FileInfo);

  // 5. Allocate buffer to read the file content
  Buffer = NULL;
  Status = gBS->AllocatePool (EfiBootServicesData, FileSize, &lv->value);
  if (EFI_ERROR (Status)) {
    Print(L"Failed to allocate memory for file content: %r\n", Status);
    FileHandle->Close(FileHandle);
    Root->Close(Root);
    goto errdone;
  }

  // 6. Read the file content
  BufferSize = (UINTN)FileSize; // BufferSize must be UINTN for Read()
  Status = FileHandle->Read (
                         FileHandle,
                         &BufferSize,
                         lv->value
                         );
  if (EFI_ERROR (Status)) {
    Print(L"Failed to read file: %r\n", Status);
    gBS->FreePool(Buffer);
    FileHandle->Close(FileHandle);
    Root->Close(Root);
    goto errdone;
  }

  lv->length = (UINT32)BufferSize;
  Print(L"Successfully read %u bytes from %s.\n", (UINT32)BufferSize, FilePath);

  // Now 'Buffer' contains the content of X64.efi.
  // You can process this content (e.g., parse it as an EFI executable)

  // Example: print a few bytes (assuming it's a binary file)
  // Be careful printing raw binary data to the console, it might not be readable.
  // For demonstration, let's print the first 16 bytes in hex.

  SBC_mem_print_bin("First 16 byte", (UINT8 *)lv->value, 16);

  ret = SBCOK;
errdone:
  // 7. Close the file and volume handles
  FileHandle->Close(FileHandle);
  Root->Close(Root);
  gBS->FreePool(Buffer);

  return ret;
  

}

SBCStatus _ssbl_image_load(EFI_HANDLE ImageHandle, LV_t *lv)
{
  SBCStatus                       ret = SBCFAIL;
  EFI_STATUS                      Status;
  EFI_SIMPLE_FILE_SYSTEM_PROTOCOL *SimpleFileSystem;
  EFI_FILE_PROTOCOL               *Root;
  EFI_FILE_PROTOCOL               *FileHandle;
  UINTN                           BufferSize;
  VOID                            *Buffer;
  EFI_DEVICE_PATH_PROTOCOL        *DevicePath;
  EFI_LOADED_IMAGE_PROTOCOL       *LoadedImage;
  EFI_HANDLE                      *HandleBuffer;
  UINTN                           NumberOfHandles;
  UINTN                           Index;
  CHAR16                          FilePath[] = L"\\EFI\\BOOT\\SSBL.efi"; // Path relative to the root of the file system
  BOOLEAN                         FoundFs1 = FALSE;
  EFI_DEVICE_PATH_TO_TEXT_PROTOCOL *DevicePathToText = NULL;
  CHAR16                          *DevicePathStr = NULL;
  CONST CHAR16                     *deviceidnetiifer = L"NVMe";


  // 1. Get the Loaded Image Protocol to determine the current device
  //    This is one way to find the file system where your current image is located.
  //    You could also iterate all SimpleFileSystem protocols to find FS1 explicitly.
  Status = gBS->OpenProtocol (
                  ImageHandle,
                  &gEfiLoadedImageProtocolGuid,
                  (VOID **)&LoadedImage,
                  ImageHandle,
                  NULL,
                  EFI_OPEN_PROTOCOL_GET_PROTOCOL
                  );
  if (EFI_ERROR (Status)) {
    Print(L"Failed to open LoadedImageProtocol: %r\n", Status);
    goto errdone;
  }

  // 2. Locate all Simple File System Protocols
  Status = gBS->LocateHandleBuffer (
                  ByProtocol,
                  &gEfiSimpleFileSystemProtocolGuid,
                  NULL,
                  &NumberOfHandles,
                  &HandleBuffer
                  );
  if (EFI_ERROR (Status)) {
    Print(L"Failed to locate SimpleFileSystemProtocol handles: %r\n", Status);
    goto errdone;
  }

  Print(L"Number of HandleBuffre : %d \n", NumberOfHandles);

  for (Index = 0; Index < NumberOfHandles; Index++) {
    Status = gBS->OpenProtocol (
                    HandleBuffer[Index],
                    &gEfiSimpleFileSystemProtocolGuid,
                    (VOID **)&SimpleFileSystem,
                    ImageHandle,
                    NULL,
                    EFI_OPEN_PROTOCOL_GET_PROTOCOL
                    );
    if (EFI_ERROR (Status)) {
      continue; // Skip if we can't open this instance
    }

    gBS->HandleProtocol(HandleBuffer[Index], &gEfiDevicePathProtocolGuid, (VOID**)&DevicePath);
    gBS->LocateProtocol(&gEfiDevicePathToTextProtocolGuid, NULL, (VOID**)&DevicePathToText);
    DevicePathStr = DevicePathToText->ConvertDevicePathToText(DevicePath, FALSE, FALSE);

    Print(L"Device path str : %s \n", DevicePathStr);
    if (StrStr((CONST CHAR16 *)DevicePathStr, deviceidnetiifer) == NULL) {
      Print(L"NVMe path NOT find \n");
      continue;
    }

    Status = SimpleFileSystem->OpenVolume (SimpleFileSystem, &Root);
    if (EFI_ERROR (Status)) {
      Print(L"Failed to open volume: %r\n", Status);
      continue;
    }

    FoundFs1 = TRUE; // Assuming we found the correct file system
    Print(L"Found a file system, attempting to open: %s\n", FilePath);
    break; // Found the file system, exit loop
  }

  gBS->FreePool(HandleBuffer);

  if (!FoundFs1) {
    Print(L"Could not locate the desired file system (FS1:).\n");
    ret = SBCNOTFND;
    goto errdone;
  }

  // 3. Open the X64.efi file
  Status = Root->Open (
                    Root,
                    &FileHandle,
                    FilePath,
                    EFI_FILE_MODE_READ,
                    0 // Attributes: no special attributes for reading
                    );
  if (EFI_ERROR (Status)) {
    Print(L"Failed to open file %s: %r\n", FilePath, Status);
    Root->Close(Root);
    goto errdone;
  }

  // 4. Get the file size
  EFI_FILE_INFO *FileInfo;
  BufferSize = 0;
  // First call to GetInfo with BufferSize = 0 to get the required buffer size
  Status = FileHandle->GetInfo (
                         FileHandle,
                         &gEfiFileInfoGuid,
                         &BufferSize,
                         NULL
                         );
  if (Status != EFI_BUFFER_TOO_SMALL) {
    Print(L"Failed to get file info (first call): %r\n", Status);
    FileHandle->Close(FileHandle);
    Root->Close(Root);
    goto errdone;
  }

  Status = gBS->AllocatePool (EfiBootServicesData, BufferSize, (VOID **)&FileInfo);
  if (EFI_ERROR (Status)) {
    Print(L"Failed to allocate memory for file info: %r\n", Status);
    FileHandle->Close(FileHandle);
    Root->Close(Root);
    goto errdone;
  }

  Status = FileHandle->GetInfo (
                         FileHandle,
                         &gEfiFileInfoGuid,
                         &BufferSize,
                         FileInfo
                         );
  if (EFI_ERROR (Status)) {
    Print(L"Failed to get file info (second call): %r\n", Status);
    gBS->FreePool(FileInfo);
    FileHandle->Close(FileHandle);
    Root->Close(Root);
    goto errdone;
  }

  UINT64 FileSize = FileInfo->FileSize;
  Print(L"File size of %s: %llu bytes\n", FilePath, FileSize);
  gBS->FreePool(FileInfo);

  // 5. Allocate buffer to read the file content
  Buffer = NULL;
  Status = gBS->AllocatePool (EfiBootServicesData, FileSize, &lv->value);
  if (EFI_ERROR (Status)) {
    Print(L"Failed to allocate memory for file content: %r\n", Status);
    FileHandle->Close(FileHandle);
    Root->Close(Root);
    goto errdone;
  }

  // 6. Read the file content
  BufferSize = (UINTN)FileSize; // BufferSize must be UINTN for Read()
  Status = FileHandle->Read (
                         FileHandle,
                         &BufferSize,
                         lv->value
                         );
  if (EFI_ERROR (Status)) {
    Print(L"Failed to read file: %r\n", Status);
    gBS->FreePool(Buffer);
    FileHandle->Close(FileHandle);
    Root->Close(Root);
    goto errdone;
  }

  lv->length = (UINT32)BufferSize;
  Print(L"Successfully read %u bytes from %s.\n", (UINT32)BufferSize, FilePath);

  // Now 'Buffer' contains the content of X64.efi.
  // You can process this content (e.g., parse it as an EFI executable)

  // Example: print a few bytes (assuming it's a binary file)
  // Be careful printing raw binary data to the console, it might not be readable.
  // For demonstration, let's print the first 16 bytes in hex.

  SBC_mem_print_bin("First 16 byte", (UINT8 *)lv->value, 16);

  ret = SBCOK;
errdone:
  // 7. Close the file and volume handles
  FileHandle->Close(FileHandle);
  Root->Close(Root);
  gBS->FreePool(Buffer);

  return ret;
  

}

EFI_STATUS efi_boot_fsbl_load(LV_t *lv)
{
  EFI_STATUS                          Status;
  EFI_HANDLE                          *HandleBuffer;
  UINTN                               NumberOfHandles;
  EFI_SIMPLE_FILE_SYSTEM_PROTOCOL     *SimpleFileSystem;
  EFI_FILE_PROTOCOL                   *RootFs = NULL;
  EFI_FILE_PROTOCOL                   *EfiDir = NULL;
  EFI_FILE_PROTOCOL                   *BootDir = NULL;
  EFI_FILE_PROTOCOL                   *X64File = NULL;
  EFI_FILE_INFO                       *FileInfo = NULL;
  UINTN                               FileInfoSize = 0;
//VOID                                *FileBuffer = NULL;
//UINTN                               FileSize = 0;

  // 1. Locate all Simple File System Protocol instances
  Status = gBS->LocateHandleBuffer (
                  ByProtocol,
                  &gEfiSimpleFileSystemProtocolGuid,
                  NULL,
                  &NumberOfHandles,
                  &HandleBuffer
                  );
  if (EFI_ERROR (Status)) {
    Print(L"Failed to locate Simple File System Protocol: %r\n", Status);
    return Status;
  }


  Print(L"Number of Handles %d \n", NumberOfHandles);
  // Iterate through found file systems to find the one containing /EFI/BOOT/X64.efi
  // In a real scenario, you might have logic to identify the correct ESP.
  // For simplicity, we'll try the first one here.
  for (UINTN Index = NumberOfHandles - 1; Index < NumberOfHandles; Index++) {
    Status = gBS->HandleProtocol (
                    HandleBuffer[Index],
                    &gEfiSimpleFileSystemProtocolGuid,
                    (VOID **)&SimpleFileSystem
                    );
    if (EFI_ERROR (Status)) {
      Print(L"Could not find a HandleProtocol file system.\n");
      continue;
    }

    // 2. Open the root volume
    Status = SimpleFileSystem->OpenVolume (
                                 SimpleFileSystem,
                                 &RootFs
                                 );
    if (!EFI_ERROR (Status)) {
      // Found a file system, try to open the EFI directory
      //break; // Exit loop, we found a potential file system
      Print(L"Could not find a Open the root volume file system.\n");
      //return EFI_NOT_FOUND;
      break;
    }
  }

  if (RootFs == NULL) {
    Print(L"Could not find a suitable file system.\n");
    gBS->FreePool(HandleBuffer);
    return EFI_NOT_FOUND;
  }

  // 3. Navigate to /EFI/BOOT/
  // Open EFI directory
  Status = RootFs->Open (
                     RootFs,
                     &EfiDir,
                     L"EFI",
                     EFI_FILE_MODE_READ,
                     0 // Attributes are 0 for directories
                     );
  if (EFI_ERROR (Status)) {
    Print(L"Failed to open EFI directory: %r\n", Status);
    goto Exit;
  }

  // Open BOOT directory
  Status = EfiDir->Open (
                     EfiDir,
                     &BootDir,
                     L"BOOT",
                     EFI_FILE_MODE_READ,
                     0
                     );
  if (EFI_ERROR (Status)) {
    Print(L"Failed to open BOOT directory: %r\n", Status);
    goto Exit;
  }

  // 4. Open X64.efi file
  Status = BootDir->Open (
                     BootDir,
                     &X64File,
                     L"FSBL.efi",
                     EFI_FILE_MODE_READ, // Open for reading
                     0 // Not creating, so attributes are 0
                     );
  if (EFI_ERROR (Status)) {
    Print(L"Failed to open X64.efi: %r\n", Status);
    goto Exit;
  }

  // 5. Get File Size
  FileInfoSize = 0;
  // First call to GetInfo to get the required buffer size
  Status = X64File->GetInfo (
                      X64File,
                      &gEfiFileInfoGuid,
                      &FileInfoSize,
                      NULL
                      );
  if (Status == EFI_BUFFER_TOO_SMALL) {
    Status = gBS->AllocatePool (
                    EfiBootServicesData,
                    FileInfoSize,
                    (VOID **)&FileInfo
                    );
    if (EFI_ERROR (Status)) {
      Print(L"Failed to allocate memory for FileInfo: %r\n", Status);
      goto Exit;
    }
    // Second call to GetInfo to actually get the info
    Status = X64File->GetInfo (
                        X64File,
                        &gEfiFileInfoGuid,
                        &FileInfoSize,
                        FileInfo
                        );
  }
  if (EFI_ERROR (Status)) {
    Print(L"Failed to get file info for X64.efi: %r\n", Status);
    goto Exit;
  }

  lv->length = FileInfo->FileSize;
  Print(L"X64.efi file size: %lu bytes\n", lv->length);

  // 6. Read the File Contents
  Status = gBS->AllocatePool (
                  EfiBootServicesData,
                  lv->length,
                  (VOID **)&lv->value
                  );
  if (EFI_ERROR (Status)) {
    Print(L"Failed to allocate memory for file buffer: %r\n", Status);
    goto Exit;
  }

  Status = X64File->Read (
                      X64File,
                      (UINTN *)&lv->length, // Pass pointer to size, it will be updated with bytes read
                      lv->value
                      );
  if (EFI_ERROR (Status)) {
    Print(L"Failed to read X64.efi: %r\n", Status);
    goto Exit;
  }

  Print(L"Successfully read X64.efi into memory at address 0x%lx. Read %lu bytes.\n", (UINTN)lv->value, lv->length);

  // At this point, FileBuffer contains the entire content of X64.efi
  // You can now process this buffer as needed (e.g., parse it, execute it, etc.)

Exit:
  // 7. Close File Handles and Free Resources
  if (FileInfo != NULL) {
    gBS->FreePool(FileInfo);
  }

  if (X64File != NULL) {
    X64File->Close(X64File);
  }
  if (BootDir != NULL) {
    BootDir->Close(BootDir);
  }
  if (EfiDir != NULL) {
    EfiDir->Close(EfiDir);
  }
  if (RootFs != NULL) {
    RootFs->Close(RootFs);
  }
  if (HandleBuffer != NULL) {
    gBS->FreePool(HandleBuffer);
  }

  return Status;
}

SBCStatus  _read_fsbl_image(LV_t *lv)
{
    SBCStatus           ret = SBCOK;
    //UINT16              *fname = L"LeoTest.efi";
    EFI_HANDLE          handle = NULL;
    UINT16              *fsblid  = STRING_TOKEN(STR_FSBL_F_NAME);

    SBC_RET_VALIDATE_ERRCODEMSG((lv != NULL), SBCNULLP, "Output buffer is Nill");

    //Investigate file size
    ret = SBC_GetFileSize(fsblid, ((UINTN *)&lv->length));
    dprint("FSBL File Size : %d , Status : %d",  lv->length, ret);
    SBC_RET_VALIDATE_ERRCODEMSG(((ret != SBCFAIL) && (lv->length > 0)), ret, "FSBL F Size fail or File not found");


    //Allocate the File data buffer
    //It must release from caller
    lv->value = AllocateZeroPool((UINTN)lv->length);
    SBC_RET_VALIDATE_ERRCODEMSG((lv->value != NULL), SBCNULLP, "Output buffer create Nill");

    //Find the File handle protocol object
    SBC_FileSysFindHndl(&handle);
    SBC_RET_VALIDATE_ERRCODEMSG((handle != NULL), SBCNULLP, "Handle find fail");

    ret = SBC_ReadFile(handle, fsblid, lv);
    SBC_RET_VALIDATE_ERRCODEMSG((ret == SBCOK), ret, "FSBL read fail");


    //SBC_external_mem_print_bin((CHAR8 *)fsblid, lv->value, lv->length);

    return ret;

errdone:

    if (lv->value) {
        gBS->FreePool(lv->value);
        lv->value = NULL;
    }
    return ret;

}


SBCStatus _nvme_get_serial(hw_uniqueinfo_t *p)
{
    SBCStatus                 ret = SBCFAIL;
    EFI_STATUS                Status;
    EFI_HANDLE                *HandleBuffer;
    UINTN                     HandleCount;
    UINTN                     Index;
    EFI_NVM_EXPRESS_PASS_THRU_PROTOCOL *NvmePassThru;
    EFI_NVM_EXPRESS_COMMAND                   Command;
    EFI_NVM_EXPRESS_PASS_THRU_COMMAND_PACKET  CommandPacket;
    EFI_NVM_EXPRESS_COMPLETION                Completion;
    NVME_ADMIN_CONTROLLER_DATA                ControllerData;


    // Locate handles that support the NVMe Pass Thru Protocol.
    Status = gBS->LocateHandleBuffer(
                        ByProtocol,
                        &gEfiNvmExpressPassThruProtocolGuid,
                        NULL,
                        &HandleCount,
                        &HandleBuffer);
    if (EFI_ERROR(Status)) {
        Print(L"Error: No NVMe devices found - %r\n", Status);
        ret = SBCFAIL;
        goto errdone;
    }

    Print(L"Found %u NVMe device(s).\n", HandleCount);

    for (Index = 0; Index < HandleCount; Index++) {
        // Get the NVMe Pass Thru Protocol from the current handle.
        Status = gBS->HandleProtocol(
                           HandleBuffer[Index],
                           &gEfiNvmExpressPassThruProtocolGuid,
                           (VOID**)&NvmePassThru);
        if (EFI_ERROR(Status)) {
            Print(L"Error: Could not access NVMe Pass Thru on device %u - %r\n", Index, Status);
            continue;
        }

        // Allocate a buffer for the NVMe Identify Controller data.
        // The Identify Controller data is 4096 bytes.
        UINT32 BufferSize = 4096;
        VOID *Buffer = AllocatePool(BufferSize);
        if (Buffer == NULL) {
            Print(L"Error: Failed to allocate memory for device %u\n", Index);
            continue;
        }
        SetMem(Buffer, BufferSize, 0);

        // Prepare the NVMe Identify Controller command.
        // Opcode 0x06 is the Identify command. Setting NSID to 0 indicates we want controller data.
        // The lower 8 bits of Cdw10 (called CNS) must be set to 1 for Identify Controller.

        ZeroMem (&CommandPacket, sizeof (EFI_NVM_EXPRESS_PASS_THRU_COMMAND_PACKET));
        ZeroMem (&Command, sizeof (EFI_NVM_EXPRESS_COMMAND));
        ZeroMem (&Completion, sizeof (EFI_NVM_EXPRESS_COMPLETION));

        //Command.Cdw0.Opcode = 0x06; // Identify Command opcode
        Command.Cdw0.Opcode = NVME_ADMIN_IDENTIFY_CMD;
        Command.Nsid = 0;
        Command.Cdw10 = 1;    // CNS = 1 ---> Identify controller.
        CommandPacket.NvmeCmd        = &Command;
        CommandPacket.NvmeCompletion = &Completion;
        CommandPacket.TransferBuffer = &ControllerData;
        CommandPacket.TransferLength = sizeof (ControllerData);
        CommandPacket.CommandTimeout = EFI_TIMER_PERIOD_SECONDS (5);
        CommandPacket.QueueType      = NVME_ADMIN_QUEUE;


                //
        // Set bit 0 (Cns bit) to 1 to identify a controller
        //
        Command.Cdw10 = 1;
        Command.Flags = CDW10_VALID;
        Status = NvmePassThru->PassThru(
                       NvmePassThru,
                       0,           // NamespaceId is 0 for controller command.
                       &CommandPacket,
                       NULL);
        if (EFI_ERROR(Status)) {
            Print(L"Error: NVMe Identify command failed on device %u - %r\n", Index, Status);
            FreePool(Buffer);
            continue;
        }

        // Interpret the buffer as NVME_CONTROLLER_DATA.
        NVME_CONTROLLER_DATA *nvme_ctrldata =
            (NVME_CONTROLLER_DATA *)CommandPacket.TransferBuffer;

        //NVME_CONTROLLER_DATA *ControllerData = (NVME_CONTROLLER_DATA *)Buffer;

        // Copy the 20-byte serial number into a local buffer and null-terminate it.
        CHAR8 Serial[21];
        CopyMem(Serial, nvme_ctrldata->SerialNumber, 20);
        Serial[20] = '\0';

        // Trim trailing spaces from the serial number.
        for (INTN i = 19; i >= 0; i--) {
            if (Serial[i] == ' ')
                Serial[i] = '\0';
            else
                break;
        }

        Print(L"NVMe Device %u Serial Number: %a\n", Index, Serial);
        //SBC_mem_print_bin("NVME DEV SN", (UINT8 *)Serial, 32);
        p->nvmesnl = strlen(Serial);
        CopyMem(p->nvmesn, Serial, p->nvmesnl);
        FreePool(Buffer);
        break;
    }

    ret = SBCOK;
errdone:
    if (HandleBuffer) {
        FreePool(HandleBuffer);
    }
    return ret;
}

static SBCStatus _baseboard_sn(hw_uniqueinfo_t *p)
{
    SBCStatus ret = SBCFAIL;
    EFI_SMBIOS_PROTOCOL *Smbios;
    EFI_STATUS Status;
    EFI_SMBIOS_HANDLE SmbiosHandle = SMBIOS_HANDLE_PI_RESERVED;
    SMBIOS_TABLE_TYPE2 *Type2Record; // Base Board Information
    EFI_SMBIOS_TABLE_HEADER *Record;
    UINT32 cnt = 0;


    SBC_RET_VALIDATE_ERRCODEMSG((p != NULL), SBCNULLP, "HW structure NIll");

    Status = gBS->LocateProtocol(&gEfiSmbiosProtocolGuid, NULL, (VOID **)&Smbios);
    SBC_RET_VALIDATE_ERRCODEMSG((Status == EFI_SUCCESS), SBCPROTO, "Smbiod Protocol Not found");

    p->mmsnl = 0;
    while(!EFI_ERROR((Status = Smbios->GetNext(Smbios, &SmbiosHandle, NULL, &Record, NULL)))) {
        //dprint("Record->Type : %d\n", Record->Type);
        if(Record->Type == SMBIOS_TYPE_BASEBOARD_INFORMATION) {

            Type2Record = (SMBIOS_TABLE_TYPE2 *)Record;
            // Extract Serial Number (this is an index into the string table)
            UINT8 SerialNumberIndex = Type2Record->SerialNumber;
            //UINT8 SerialNumberIndex = Type2Record->Manufacturer;
            //CHAR8 *SerialNumberString = (CHAR8 *)(Record);
            CHAR8 *SerialNumberString = (((CHAR8 *)Record) + Record->Length);
            SBC_external_mem_print_bin("_baseboard record", (UINT8 *)SerialNumberString, 0x79 - Record->Length);
            dprint("serial number index : %d (Record Length : 0x%x)",
                   SerialNumberIndex, Record->Length);
            if (SerialNumberIndex > 0) {
#if 0
                for (UINT8 i = 1; i < SerialNumberIndex; i++) {

                    while (*SerialNumberString != '\0') {
                        //p->mbsn[p->mbsnl++] = *SerialNumberString;
                        SerialNumberString++;
                        cnt++;
                    }
                    SerialNumberString++;
                    cnt++;
                }

#else

                for (UINT16 Index = 1; Index <= SerialNumberIndex; Index++) {
                    if (SerialNumberIndex == Index) {
                        break;
                    }

                    // Skip String
                    for (; *SerialNumberString != 0; SerialNumberString++) {
                    }

                    SerialNumberString++;
                    if (*SerialNumberString == 0) {
                        SBC_mem_print_bin("_baseboard_sn pass", (UINT8 *)SerialNumberString, p->mbsnl);
                    }
                    cnt++;
                }
#endif
                Print(L"_baseboard_sn Serial Number: %a (Count : %d)\n",
                      SerialNumberString,
                      cnt);


                p->mbsnl = strlen(SerialNumberString);
                SBC_mem_print_bin("_baseboard_sn", (UINT8 *)SerialNumberString, p->mbsnl);
                CopyMem(p->mbsn, SerialNumberString, p->mbsnl);


            }
        }
    }
    ret = SBCOK;

errdone:

    return ret;
}

static SBCStatus _memorydevice_sn(hw_uniqueinfo_t *p)
{
    SBCStatus ret = SBCFAIL;
    EFI_SMBIOS_PROTOCOL *Smbios;
    EFI_STATUS Status;
    EFI_SMBIOS_HANDLE SmbiosHandle = SMBIOS_HANDLE_PI_RESERVED;
    SMBIOS_TABLE_TYPE17 *Type2Record; // Base Board Information
    EFI_SMBIOS_TABLE_HEADER *Record;
    UINT32 cnt = 0;


    SBC_RET_VALIDATE_ERRCODEMSG((p != NULL), SBCNULLP, "HW structure NIll");

    Status = gBS->LocateProtocol(&gEfiSmbiosProtocolGuid, NULL, (VOID **)&Smbios);
    SBC_RET_VALIDATE_ERRCODEMSG((Status == EFI_SUCCESS), SBCPROTO, "Smbiod Protocol Not found");

    p->mmsnl = 0;
    while(!EFI_ERROR((Status = Smbios->GetNext(Smbios, &SmbiosHandle, NULL, &Record, NULL)))) {
        //dprint("Record->Type : %d\n", Record->Type);
        if(Record->Type == SMBIOS_TYPE_MEMORY_DEVICE) {

            Type2Record = (SMBIOS_TABLE_TYPE17 *)Record;
            // Extract Serial Number (this is an index into the string table)
            UINT8 SerialNumberIndex = Type2Record->SerialNumber;
            dprint("serial number index : %d", SerialNumberIndex);
            CHAR8 *SerialNumberString = (((CHAR8 *)Record) + Record->Length);
            SBC_external_mem_print_bin("_memorydevice_sn record", (UINT8 *)SerialNumberString, 0x8B -  Record->Length);
            if (SerialNumberIndex > 0) {
#if 0
                for (UINT8 i = 1; i < SerialNumberIndex; i++) {

                    while (*SerialNumberString != '\0') {
                        //p->mbsn[p->mbsnl++] = *SerialNumberString;
                        SerialNumberString++;
                        cnt++;
                    }
                    SerialNumberString++;
                    cnt++;
                }

#else

                for (UINT16 Index = 1; Index <= SerialNumberIndex; Index++) {
                    if (SerialNumberIndex == Index ) {
                        break;
                    }

                    // Skip String
                    for (; *SerialNumberString != 0; SerialNumberString++);

                    SerialNumberString++;
                    if (*SerialNumberString == 0) {
                        Print(L"f you pass in a -1 you will always get here\n");
                    }
                    cnt++;
                }
#endif
                Print(L"_memorydevice_sn Serial Number: %a (%d)\n",
                      SerialNumberString,cnt);
                p->mmsnl = strlen(SerialNumberString);
                CopyMem(p->mmsn, SerialNumberString, p->mmsnl);
                SBC_mem_print_bin("_memorydevice_sn", (UINT8 *)p->mmsn, p->mmsnl);

            }
        }
    }
    ret = SBCOK;

errdone:

    return ret;
}


SBCStatus  _baseanswer_store(VOID *p)
{
    SBCStatus ret = SBCOK;

    VOID *blkio = NULL;
    base_ansid_t *h = NULL;
    UINT8 loadbuf[BASE_ANS_BLK_LEN] = {0, };
    UINT8 *cpy = NULL;
    UINT32 ldlen = BASE_ANS_BLK_LEN;

    h = (base_ansid_t *)p;
    
    //SBC_RET_VALIDATE_ERRCODEMSG((p != NULL), SBCNULLP, "Invalid parameter");

    // Find the Block device handlef for SBC Raw Partition
    ret = SBC_FindBlkIoHandle(&blkio);
    if (ret != SBCOK || blkio == NULL) {
      Print(L"SBC_FindBlockIoHandle fail (%p)\n", blkio);
      goto errdone;
    }

    ret = SBC_RawPrtReadBlock(blkio, 
                              (VOID *)loadbuf, 
                              &ldlen, 
                              BASE_ANS_BLK_LBA);
    if (ret != SBCOK) {
        Print(L"SBC_RawPrtReadBlock fail (%p)\n", blkio);
        goto errdone;
    }
    

    // TODO : Fill up the Base Answer in RAM buffer 
    cpy = (UINT8 *)&loadbuf[BASE_ANS_SAT_OFFSET];
    Print(L"Encrypt Message Length : %d \n", h->msglen);
    CopyMem((void *)cpy, &h->msglen, sizeof h->msglen);
    cpy += sizeof h->msglen;

    CopyMem((void *)cpy, h->encmsg, h->msglen );
    cpy += h->msglen;

    CopyMem((void *)cpy, h->tag, BASE_ANS_TAG_LEN);
    cpy += BASE_ANS_TAG_LEN;

   
    SBC_mem_print_bin("Store Key", h->key,  32);
    CopyMem((void *)cpy, h->key, BASE_ANS_KEY_STR);
    cpy += BASE_ANS_KEY_STR;

    

    CopyMem((void *)cpy, h->iv, BASE_ANS_IV_KEY_STR);


    SBC_mem_print_bin("Base Ans write", loadbuf, 512);



    ret = SBC_RawPrtBlockWrite(blkio, loadbuf, BASE_ANS_BLK_LEN, BASE_ANS_BLK_LBA);
    if (ret != SBCOK) {
      //Print(L"SBC Raw Partition Base Answer write fail \n");
      goto errdone;
    }

    ret = SBCOK;

errdone:
    return ret;

}

static SBCStatus _baseanswer_extract_from_disk(base_ansid_t *p)
{
  SBCStatus ret = SBCOK;
  VOID *blkio = NULL;
  
  UINT32  anslen = 0U;
  UINT8   streams[512] = {0,};
  UINT32  offset = 0;

  SBC_RET_VALIDATE_ERRCODEMSG((p != NULL), SBCNULLP, "Invalid parameter");

  // Find the Block device handlef for SBC Raw Partition
  ret = SBC_FindBlkIoHandle(&blkio);
  if (ret != SBCOK || blkio == NULL) {
    Print(L"SBC_FindBlockIoHandle fail (%p)\n", blkio);
    goto errdone;
  }

  anslen = BASE_ANS_BLK_LEN;
  // NOTES : It SHOLUD be consider for TAG size if Message is encrypt to  AES-GCM mode
  ret = SBC_RawPrtReadBlock(blkio, (VOID *)streams,  &anslen , BASE_ANS_BLK_LBA);
  if (ret != SBCOK) {
    Print(L"SBC_RawPrtReadBlock fail (%p)\n", blkio);
    goto errdone;
  }
  //Print(L"%a:%d \n",__FUNCTION__, __LINE__);


  // Copy Length
  offset = BASE_ANS_SAT_OFFSET;
  //SBC_mem_print_bin("Load Buf", (UINT8 *)&streams[offset], 256);
  CopyMem((void *)&p->msglen, (void *)&streams[offset], 4);
  //p->msglen = 16; // later remove 
  offset += 4;

  CopyMem((void *)p->encmsg, (void *)&streams[offset], p->msglen);
  offset += p->msglen;

  CopyMem((void *)p->tag, (void *)&streams[offset], BASE_ANS_TAG_LEN);
  offset += BASE_ANS_TAG_LEN;

  CopyMem((void *)p->key, (void *)&streams[offset], BASE_ANS_KEY_STR);
  offset += BASE_ANS_KEY_STR;

  CopyMem((void *)p->iv, (void *)&streams[offset], BASE_ANS_IV_KEY_STR);
  offset += BASE_ANS_IV_KEY_STR;

  SBC_mem_print_bin("Enc Msg Len", (UINT8 *)&p->msglen, 4);
  SBC_mem_print_bin("Enc Message", p->encmsg, p->msglen);
  SBC_mem_print_bin("Tag Message", p->tag, BASE_ANS_TAG_LEN);
  SBC_mem_print_bin("Enc Key", p->key, BASE_ANS_KEY_STR);
  SBC_mem_print_bin("Enc IV", p->iv, BASE_ANS_IV_KEY_STR);

  




errdone:
    return ret;
}

SBCStatus SBC_BaseAnswerEncryptStore(UINT8* msg, UINT32 msgl, UINT8 *key, UINT32 keyl)
{
    SBCStatus ret = SBCOK;
    base_ansid_t ansid;

    SBC_AESContext aesctx;
    SBC_AESGcmCtx  ctx;
    UINT8 iv[BASE_ANS_IV_KEY_STR] = {0, };


    ZeroMem((void *)&ansid ,sizeof ansid);
    CopyMem((void *)ansid.key, key, BASE_ANS_KEY_STR);
    CopyMem((void *)ansid.iv, iv, BASE_ANS_IV_KEY_STR);


    // A. Encrypt the Message 

    ctx.key.value = ansid.key;
    ctx.key.length = BASE_ANS_KEY_STR;
    ctx.iv.value = ansid.iv;
    ctx.iv.length = BASE_ANS_IV_KEY_STR;
    ctx.aad.value = NULL;
    ctx.aad.length = 0;
    ctx.msg.value = msg;
    ctx.msg.length = msgl;
    ctx.tag.value = ansid.tag;
    ctx.tag.length = BASE_ANS_TAG_LEN;

    ctx.out.value = ansid.encmsg;
    ctx.out.length = sizeof ansid.encmsg;

    

    aesctx.gcm = &ctx;
    aesctx.algoid = SBC_CIPHER_AES_GCM;

    ret = SBC_AESEncrypt(&aesctx);
    if (ret != SBCOK) {
      Print(L"Base Encrypt Fail \n");
      goto errdone;
    }

    ansid.msglen = ctx.out.length;

    ret = _baseanswer_store((VOID *)&ansid);
    if (ret != SBCOK) {
      Print(L"Base Answer storing fail \n");
      goto errdone;
    }


    ret = SBCOK;
errdone:

    return ret;

}



SBCStatus  SBC_BaseAnswerValidate(UINT8 *answer, UINTN answerl)
{
    SBCStatus ret = SBCOK;
    //UINT8 rdbuf[256];
    //UINT8 baseanswer[256] = {0, };
    base_ansid_t ansid;
    SBC_AESContext aesctx;
    SBC_AESGcmCtx  ctx;

    UINT8 decbuf[BASE_ANS_STREAM_LEN] = {0,};

    SBC_RET_VALIDATE_ERRCODEMSG((answer != NULL), SBCNULLP, "Answer is Nill");

    ZeroMem((void *)&ctx, sizeof ctx);
    ZeroMem((void *)&aesctx, sizeof aesctx);
    ZeroMem(&ansid, sizeof ansid);

    ret = _baseanswer_extract_from_disk(&ansid);
    SBC_RET_VALIDATE_ERRCODEMSG((ret == SBCOK),ret, "Disk read fail");


    ctx.key.value = ansid.key;
    ctx.key.length = BASE_ANS_KEY_STR;
    ctx.iv.value = ansid.iv;
    ctx.iv.length = BASE_ANS_IV_KEY_STR; 
    ctx.aad.value = NULL;
    ctx.aad.length = 0;
    ctx.msg.value = ansid.encmsg;
    ctx.msg.length = ansid.msglen;
    ctx.tag.value = ansid.tag;
    ctx.tag.length = BASE_ANS_TAG_LEN;

    ctx.out.value = decbuf;
    ctx.out.length = BASE_ANS_STREAM_LEN;

    aesctx.gcm = &ctx;
    aesctx.algoid = SBC_CIPHER_AES_GCM;

    if (SBC_AESDecrypt(&aesctx) != SBCOK) {
      Print(L"Base Answer Decrypt fail \n");
      ret = SBCFAIL;
      goto errdone;
    }

    SBC_mem_print_bin("decrypt msg", answer, answerl);
    SBC_mem_print_bin("decrypt msg", decbuf, ctx.out.length);

    if (CompareMem((const void *)decbuf, (const void *)answer, answerl) != 0) {
      Print(L"Base Answer validate Fail \n");
      ret = SBCFAIL;
      goto errdone;
    }

    Print(L"Base Answer validate Success \n");



errdone:
    return ret;

}




SBCStatus SBC_GenDeviceID(UINT8 *devid)
{
    SBCStatus ret = SBCOK;
    //at_key_t key;
    LV_t    rdlv = {
        .value = NULL,
        .length = 0
    };
    
    hw_uniqueinfo_t info;
    UINT8 *computebuf = NULL;
    UINTN cnt = 0;

    SBC_RET_VALIDATE_ERRCODEMSG((devid != NULL),SBCNULLP, "Out buffer Nill");

   


    // TODO : read the device information 
    ZeroMem((void *)&info, sizeof info);


    _baseboard_sn(&info);
    SBC_external_mem_print_bin("BaseBoard SN", info.mbsn,info.mbsnl);
    SBC_mem_print_bin("BaseBoard SN", info.mbsn,info.mbsnl);

    _memorydevice_sn(&info);
    SBC_external_mem_print_bin("MemoryDevice SN", info.mmsn, info.mmsnl);
    SBC_mem_print_bin("MemoryDevice SN", info.mmsn, info.mmsnl);

    _nvme_get_serial(&info);
    SBC_external_mem_print_bin("NVME SN", info.nvmesn,info.nvmesnl);
    SBC_mem_print_bin("NVME SN", info.nvmesn,info.nvmesnl);

    //_read_fsbl_image(&rdlv);
    efi_boot_fsbl_load(&rdlv);
    SBC_RET_VALIDATE_ERRCODEMSG((rdlv.value != NULL), SBCNULLP, "FSBL read fail");

    computebuf = AllocatePool(info.mbsnl + info.mmsnl + info.nvmesnl + rdlv.length);
    SBC_RET_VALIDATE_ERRCODEMSG((computebuf != NULL),SBCNULLP, "Compute buffer Nill");

    cnt = 0;
    //Print(L" cnt : %d \n", cnt);
    CopyMem((void *)&computebuf[0], info.mbsn, info.mbsnl);
    cnt = info.mbsnl;

    //Print(L"Next cnt : %d \n", cnt);
    CopyMem((void *)&computebuf[cnt], info.mmsn, info.mmsnl);
    cnt += info.mmsnl;

    //Print(L"Next Next cnt : %d \n", cnt);
    CopyMem((void *)&computebuf[cnt], info.nvmesn, info.nvmesnl);
    cnt += info.nvmesnl;

        //Print(L"Next Next cnt : %d \n", cnt);
    CopyMem((void *)&computebuf[cnt], rdlv.value, rdlv.length);
    cnt += rdlv.length;

    dprint("DICE message length  : %d", cnt);
    Print(L"DICE message length  : %d \n", cnt);
    //SBC_mem_print_bin("Device ID Raw Fmt", computebuf, cnt);
    ret = SBC_HashCompute(
                             NULL, /* Not yet used */
                             computebuf,
                             cnt,
                             devid
                          ) ;



    SBC_mem_print_bin("Device ID", devid, 32);


    
errdone:

    if(computebuf) {
        FreePool(computebuf);
    }
    return ret;

}

SBCStatus SBC_GenFWID(EFI_HANDLE *h_image, UINT8 *devid, UINT8 *fwid)
{
  SBCStatus ret       = SBCOK;
  UINT8 *temp = NULL;
  UINT8 *rdbuf = NULL;
  LV_t lv;


  lv.value = rdbuf;
  lv.length = 0;

  ret = _ssbl_image_load(h_image, &lv);
  SBC_RET_VALIDATE_ERRCODEMSG((ret == SBCOK), ret, "SSB Image load fail");
  SBC_RET_VALIDATE_ERRCODEMSG((lv.length > 0), SBCZEROL, "SSB Image length 0");

  temp = AllocateZeroPool(SBC_AT_HASH_LEN + lv.length);
  SBC_RET_VALIDATE_ERRCODEMSG((temp != NULL), SBCNULLP, "memeory creation fail");

  CopyMem((void *)&temp[0], devid, SBC_AT_HASH_LEN);
  CopyMem((void *)&temp[SBC_AT_HASH_LEN], lv.value, lv.length);

  ret = SBC_HashCompute(
                             NULL, /* Not yet used */
                             temp,
                             lv.length + SBC_AT_HASH_LEN,
                             fwid
                          ) ;

  SBC_mem_print_bin("FW ID", fwid, 32);
errdone:

  if (temp != NULL) {
    FreePool(temp);
  }

  if (lv.value != NULL) {
    FreePool(lv.value);
  }
  return ret;


}


SBCStatus SBC_GenOSID(EFI_HANDLE *h_image, UINT8 *fwid, UINT8 *osid)
{
  SBCStatus ret       = SBCOK;
  UINT8 *temp = NULL;
  UINT8 *rdbuf = NULL;
  LV_t lv;


  lv.value = rdbuf;
  lv.length = 0;

  // OS Kernel Image read 
  ret = _kernel_image_load(h_image, &lv);
  if (ret != SBCOK) {
    Print(L"Kernel Image load fail \n");
    goto errdone;
  }

  temp = AllocateZeroPool(SBC_AT_HASH_LEN + lv.length);
  SBC_RET_VALIDATE_ERRCODEMSG((temp != NULL), SBCNULLP, "memeory creation fail");

  CopyMem((void *)&temp[0], fwid, SBC_AT_HASH_LEN);
  CopyMem((void *)&temp[SBC_AT_HASH_LEN], lv.value, lv.length);

  ret = SBC_HashCompute(
                             NULL, /* Not yet used */
                             temp,
                             lv.length + SBC_AT_HASH_LEN,
                             osid
                          ) ;

  SBC_mem_print_bin("OS ID", osid, 32);
errdone:

  if (temp != NULL) {
    FreePool(temp);
  }

  if (lv.value != NULL) {
    FreePool(lv.value);
  }
  return ret;


}

//SBCStatus SBC_GenDeviceID(UINT8 *devid)
//{
//    SBCStatus ret = SBCOK;
//    at_key_t key;
//    LV_t    rdlv = {
//        .value = NULL,
//        .length = 0
//    };
//
//#ifndef  SBC_BASEANSWER_TEST
//    hw_uniqueinfo_t info;
//
//#else
//   hw_uniqueinfo_t info = {
//       .mbsn = { 0x51, 0x43, 0x51, 0x34, 0x53, 0x31, 0x32, 0x34, 0x34, 0x34, 0x30, 0x30, 0x4b, 0x52},
//       .mbsnl = 14,
//       .mmsn = {0x30, 0x30, 0x30, 0x30, 0x30, 0x30, 0x30, 0x30},
//       .mmsnl = 8,
//       .nvmesn = {0x36, 0x34, 0x37, 0x39, 0x5f, 0x41, 0x37, 0x39, 0x36, 0x5f, 0x34, 0x41,0x33, 0x30, 0x5f, 0x35, 0x43, 0x37, 0x36 },
//       .nvmesnl = 20
//   };
//
//    CHAR8 *pemkey_priv;
//    CHAR8 *pemkey_pub;
//    UINTN pemsize;
//    CONST CHAR8 *pemheader_priv="-----BEGIN PRIVATE KEY-----";
//    CONST CHAR8 *pemoffter_priv="-----END PRIVATE KEY-----";
//    CONST CHAR8 *pemheader_pub="-----BEGIN PUBLIC KEY-----";
//    CONST CHAR8 *pemoffter_pub="-----END PUBLIC KEY-----";
//   UINT8 *computebuf = NULL;
//   UINTN cnt = 0;
//#endif
//    SBC_RET_VALIDATE_ERRCODEMSG((devid != NULL),SBCNULLP, "Out buffer Nill");
//
//
//
//#ifndef  SBC_BASEANSWER_TEST
//    // TODO : read the device information
//    ZeroMem((void *)&info, sizeof info);
//#else
//
//    _baseboard_sn(&info);
//    SBC_external_mem_print_bin("BaseBoard SN", info.mbsn,info.mbsnl);
//    SBC_mem_print_bin("BaseBoard SN", info.mbsn,info.mbsnl);
//
//    _memorydevice_sn(&info);
//    SBC_external_mem_print_bin("MemoryDevice SN", info.mmsn, info.mmsnl);
//    SBC_mem_print_bin("MemoryDevice SN", info.mmsn, info.mmsnl);
//
//    _nvme_get_serial(&info);
//    SBC_external_mem_print_bin("NVME SN", info.nvmesn,info.nvmesnl);
//    SBC_mem_print_bin("NVME SN", info.nvmesn,info.nvmesnl);
//
//    //_read_fsbl_image(&rdlv);
//    efi_boot_fsbl_load(&rdlv);
//    SBC_RET_VALIDATE_ERRCODEMSG((rdlv.value != NULL), SBCNULLP, "FSBL read fail");
//
//    computebuf = AllocatePool(info.mbsnl + info.mmsnl + info.nvmesnl + rdlv.length);
//    SBC_RET_VALIDATE_ERRCODEMSG((computebuf != NULL),SBCNULLP, "Compute buffer Nill");
//
//    cnt = 0;
//    //Print(L" cnt : %d \n", cnt);
//    CopyMem((void *)&computebuf[0], info.mbsn, info.mbsnl);
//    cnt = info.mbsnl;
//
//    //Print(L"Next cnt : %d \n", cnt);
//    CopyMem((void *)&computebuf[cnt], info.mmsn, info.mmsnl);
//    cnt += info.mmsnl;
//
//    //Print(L"Next Next cnt : %d \n", cnt);
//    CopyMem((void *)&computebuf[cnt], info.nvmesn, info.nvmesnl);
//    cnt += info.nvmesnl;
//
//        //Print(L"Next Next cnt : %d \n", cnt);
//    CopyMem((void *)&computebuf[cnt], rdlv.value, rdlv.length);
//    cnt += rdlv.length;
//
//    dprint("DICE message length  : %d", cnt);
//    Print(L"DICE message length  : %d \n", cnt);
//    //SBC_mem_print_bin("Device ID Raw Fmt", computebuf, cnt);
//    ret = SBC_HashCompute(
//                             NULL, /* Not yet used */
//                             computebuf,
//                             cnt,
//                             devid
//                          ) ;
//
//
//
//    SBC_mem_print_bin("Device ID", devid, 32);
//
//#endif
//
//
//    SBC_RET_VALIDATE_ERRCODEMSG((ret == SBCOK), ret, "Hash compute fail");
//
//    SBC_DICESeedKeyPair(devid, &key);
//
//    SBC_external_mem_print_bin("Devid Private", key.d, key.dl);
//    SBC_external_mem_print_bin("Pub", key.q.value, key.ql);
//
//    SBC_ConvertRawKeyPem(
//                    key.d, key.dl,
//                    pemheader_priv, pemoffter_priv,
//                    &pemkey_priv,&pemsize
//            );
//    SBC_external_mem_print_bin("PRIV pem", (UINT8 *)pemkey_priv, (UINT32)pemsize);
//
//    SBC_ConvertRawKeyPem(
//                    key.q.value, key.ql,
//                    pemheader_pub, pemoffter_pub,
//                    &pemkey_pub,&pemsize
//            );
//    SBC_external_mem_print_bin("PUBLIC pem", (UINT8 *)pemkey_pub, (UINT32)pemsize);
//
//
//errdone:
//
//    if(computebuf) {
//        FreePool(computebuf);
//    }
//    return ret;
//
//}

