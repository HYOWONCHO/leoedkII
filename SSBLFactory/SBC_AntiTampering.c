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
#include <Library/BaseCryptLib.h>
#include <Protocol/BlockIo.h>

#include "SBC_CryptAES.h"
#include "SBC_TypeDefs.h"

#include "SBC_Util.h"
#include "SBC_Config.h"
#include "SBC_FileCtrl.h"

#include "SBC_Hashing.h"
#include "SBC_AntiTampering.h"
#include "SBC_EccSignVerify.h"
#include "SBC_X509.h"
#include "SBC_Kdf.h"


  


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

  //Print(L"Number of HandleBuffre : %d \n", NumberOfHandles);

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

    //Print(L"Device path str : %s \n", DevicePathStr);
    if (StrStr((CONST CHAR16 *)DevicePathStr, deviceidnetiifer) == NULL) {
      //Print(L"NVMe path NOT find \n");
      continue;
    }

    Status = SimpleFileSystem->OpenVolume (SimpleFileSystem, &Root);
    if (EFI_ERROR (Status)) {
      Print(L"Failed to open volume: %r\n", Status);
      continue;
    }

    FoundFs1 = TRUE; // Assuming we found the correct file system
    //Print(L"Found a file system, attempting to open: %s\n", FilePath);
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
  //Print(L"File size of %s: %llu bytes\n", FilePath, FileSize);
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

  //SBC_mem_print_bin("First 16 byte", (UINT8 *)lv->value, 16);

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

  //Print(L"Number of HandleBuffre : %d \n", NumberOfHandles);

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

    //Print(L"Device path str : %s \n", DevicePathStr);
    if (StrStr((CONST CHAR16 *)DevicePathStr, deviceidnetiifer) == NULL) {
      //Print(L"NVMe path NOT find \n");
      continue;
    }

    Status = SimpleFileSystem->OpenVolume (SimpleFileSystem, &Root);
    if (EFI_ERROR (Status)) {
      Print(L"Failed to open volume: %r\n", Status);
      continue;
    }

    FoundFs1 = TRUE; // Assuming we found the correct file system
    //Print(L"Found a file system, attempting to open: %s\n", FilePath);
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
  //Print(L"File size of %s: %llu bytes\n", FilePath, FileSize);
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

  //SBC_mem_print_bin("First 16 byte", (UINT8 *)lv->value, 16);

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


  //Print(L"Number of Handles %d \n", NumberOfHandles);
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
      //Print(L"Could not find a Open the root volume file system.\n");
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
  //Print(L"X64.efi file size: %lu bytes\n", lv->length);

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

  //Print(L"Successfully read X64.efi into memory at address 0x%lx. Read %lu bytes.\n", (UINTN)lv->value, lv->length);

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

    //Print(L"Found %u NVMe device(s).\n", HandleCount);

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
            //SBC_external_mem_print_bin("_baseboard record", (UINT8 *)SerialNumberString, 0x79 - Record->Length);
            //dprint("serial number index : %d (Record Length : 0x%x)",
            //       SerialNumberIndex, Record->Length);
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
            //dprint("serial number index : %d", SerialNumberIndex);
            CHAR8 *SerialNumberString = (((CHAR8 *)Record) + Record->Length);
            //SBC_external_mem_print_bin("_memorydevice_sn record", (UINT8 *)SerialNumberString, 0x8B -  Record->Length);
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


SBCStatus  _baseanswer_store(VOID *blkio, VOID *p)
{
    SBCStatus ret = SBCOK;

    //VOID *blkio = NULL;
    base_ansid_t *h = NULL;
    UINT8 *loadbuf;
    UINT8 *cpy = NULL;
    UINT32 ldlen = BASE_ANS_BLK_LEN;
    UINTN baseansr_lba = 0;


    h = (base_ansid_t *)p;
    
    SBC_RET_VALIDATE_ERRCODEMSG((p != NULL), SBCNULLP, "Base-answer Invalid object");
    SBC_RET_VALIDATE_ERRCODEMSG((blkio != NULL), SBCNULLP, "Block I/O Invalid object");


    baseansr_lba = (SYS_CONF_START_OFS >> SBC_RAWPRT_DFLT_SHIFT);
    ldlen = ALIGN_VALUE(SYS_SETTING_STORAGE_LEN, ((EFI_BLOCK_IO_PROTOCOL *)blkio)->Media->BlockSize);
    loadbuf = AllocateZeroPool(ldlen);
    SBC_RET_VALIDATE_ERRCODEMSG((loadbuf != NULL), SBCNULLP, "Buffer invalid object");

    ret = SBC_RawPrtReadBlock(blkio, 
                              (VOID *)loadbuf, 
                              &ldlen, 
                              baseansr_lba);
    if (ret != SBCOK) {
        Print(L"SBC_RawPrtReadBlock fail (%p)\n", blkio);
        goto errdone;
    }

//  SBC_external_mem_print_bin("Before Base Ans write",
//                             (UINT8 *)&loadbuf[SYS_CONF_RES_OFS],
//                             64);

    // TODO : Fill up the Base Answer in RAM buffer 
    cpy = (UINT8 *)&loadbuf[SYS_CONF_RES_OFS];
    CopyMem((void *)cpy, &h->msglen, sizeof h->msglen);
    //dprint("Message Len : %d", h->msglen);
    cpy += sizeof h->msglen;

    CopyMem((void *)cpy, h->encmsg, h->msglen );
    cpy += h->msglen;

    CopyMem((void *)cpy, h->iv, BASE_ANS_IV_KEY_STR);
    cpy += BASE_ANS_IV_KEY_STR;

    CopyMem((void *)cpy, h->tag, BASE_ANS_TAG_LEN);
    cpy += BASE_ANS_TAG_LEN;

    ZeroMem((void *)cpy, 16); // Reserved  bytes set to zero
//  SBC_external_mem_print_bin("After Base Ans write",
//                             (UINT8 *)&loadbuf[SYS_CONF_RES_OFS],
//                             64);



    ret = SBC_RawPrtBlockWrite(blkio, loadbuf, ldlen, baseansr_lba);
    if (ret != SBCOK) {
      //Print(L"SBC Raw Partition Base Answer write fail \n");
      goto errdone;
    }

    ret = SBCOK;

errdone:
    if (loadbuf != NULL) {
      FreePool(loadbuf);
    }
    return ret;

}

static SBCStatus _baseanswer_extract_from_disk(VOID *blkio, base_ansid_t *p)
{
  SBCStatus ret = SBCOK;

  UINT8 *loadbuf;
  UINT32 ldlen = BASE_ANS_BLK_LEN;
  UINTN baseansr_lba = 0;
  UINTN offset = 0;


  SBC_RET_VALIDATE_ERRCODEMSG((p != NULL), SBCNULLP, "Invalid parameter");


  baseansr_lba = (SYS_CONF_START_OFS >> SBC_RAWPRT_DFLT_SHIFT);
  ldlen = ALIGN_VALUE(SYS_SETTING_STORAGE_LEN, ((EFI_BLOCK_IO_PROTOCOL *)blkio)->Media->BlockSize);
  loadbuf = AllocateZeroPool(ldlen);
  SBC_RET_VALIDATE_ERRCODEMSG((loadbuf != NULL), SBCNULLP, "Buffer invalid object");

  // NOTES : It SHOLUD be consider for TAG size if Message is encrypt to  AES-GCM mode
  ret = SBC_RawPrtReadBlock(blkio, (VOID *)loadbuf,  &ldlen , baseansr_lba);
  if (ret != SBCOK) {
    Print(L"SBC_RawPrtReadBlock fail (%p)\n", blkio);
    goto errdone;
  }
  //Print(L"%a:%d \n",__FUNCTION__, __LINE__);


  // Copy Length

  offset = SYS_CONF_RES_OFS;
  CopyMem((void *)&p->msglen, (void *)&loadbuf[offset], 4);
  SBC_RET_VALIDATE_ERRCODEMSG((p->msglen > 0), SBCBSANSWNOTFND, "Base Answer Not Foudn");
  offset += 4;

  CopyMem((void *)p->encmsg, (void *)&loadbuf[offset], p->msglen);
  offset += p->msglen;

  CopyMem((void *)p->iv, (void *)&loadbuf[offset], BASE_ANS_IV_KEY_STR);
  offset += BASE_ANS_IV_KEY_STR;


  CopyMem((void *)p->tag, (void *)&loadbuf[offset], BASE_ANS_TAG_LEN);
  offset += BASE_ANS_TAG_LEN;


//dprint("Enc Msg Len : %d", p->msglen);
//SBC_mem_print_bin("Enc Message", p->encmsg, p->msglen);
//SBC_mem_print_bin("Enc IV", p->iv, BASE_ANS_IV_KEY_STR);
//SBC_mem_print_bin("Tag Message", p->tag, BASE_ANS_TAG_LEN);
  

errdone:
  return ret;
}


SBCStatus  SBC_DeviceIdKyeVerify(VOID *blkio, UINT8 *devid, UINT8 *deckey)
{
    SBCStatus ret = SBCOK;
    at_key_t key_pair;

    VOID *ctx = NULL;
    BOOLEAN retval;

    UINT8 pubkey[64] = {0,};
    UINTN pubkeyl = 0;
    UINT8 *loadbuf;
    UINT32 ldlen = BASE_ANS_BLK_LEN;
    UINTN baseansr_lba = 0;
    SBC_AESGcmCtx  decctx;
    SBC_AESContext  aesctx;

    UINTN offset = 0;
    UINTN calen = 0;

    UINT8 decbuf[2048] = {0,};


    // Generate the Public Key
    ret = SBC_DICESeedKeyPair(devid, &key_pair);
    SBC_RET_VALIDATE_ERRCODEMSG((ret == SBCOK), SBCINVPARAM, "Device ID Key-pair gen fail");


    // Device ID certificate Load 
    baseansr_lba = (SYS_CONF_START_OFS >> SBC_RAWPRT_DFLT_SHIFT);
    ldlen = ALIGN_VALUE(SYS_SETTING_STORAGE_LEN, ((EFI_BLOCK_IO_PROTOCOL *)blkio)->Media->BlockSize);
    loadbuf = AllocateZeroPool(ldlen);
    SBC_RET_VALIDATE_ERRCODEMSG((loadbuf != NULL), SBCNULLP, "Buffer invalid object");

    ret = SBC_RawPrtReadBlock(blkio, 
                              (VOID *)loadbuf, 
                              &ldlen, 
                              baseansr_lba);
    if (ret != SBCOK) {
        Print(L"SBC_RawPrtReadBlock fail (%p)\n", blkio);
        goto errdone;
    }

    CopyMem((void *)&calen, (void *)&loadbuf[0], 4);
    offset += 4;
    // Decrypt 

    decctx.msg.value = &loadbuf[offset];
    decctx.msg.length = calen;

    offset += calen;
    decctx.iv.value = &loadbuf[offset];
    decctx.iv.length = BASE_ANS_IV_KEY_STR; 
    
    offset += BASE_ANS_IV_KEY_STR;
    decctx.tag.value = &loadbuf[offset];
    decctx.tag.length = BASE_ANS_TAG_LEN;

    decctx.key.value = deckey;
    decctx.key.length = BASE_ANS_KEY_STR;

    decctx.aad.value = NULL;
    decctx.aad.length = 0;

    decctx.out.value = decbuf;
    decctx.out.length = calen;

    aesctx.gcm = &decctx;
    aesctx.algoid = SBC_CIPHER_AES_GCM;

    if (SBC_AESGcmDecrypt(&aesctx) != SBCOK) {
        eprint("DeviceID CA decrypt fail");
        ret = SBCDECFAIL;
        goto errdone;
    }


    // Get Public Key
    ret = SBC_EcGetPublicKeyFromPem((CONST UINT8 *)decbuf, calen, &ctx);
    SBC_RET_VALIDATE_ERRCODEMSG((ret == SBCOK), SBCINVPARAM, "Public key extract fail");

    retval = EcGetPubKey(ctx, pubkey, &pubkeyl);
    if(retval != TRUE) {
        ret = SBCFAIL;
        eprint("EcGetPubKey fail %r", retval);
        goto errdone;
    }

    SBC_external_mem_print_bin("Device ID Pubkey", key_pair.q.value, key_pair.ql);
    SBC_external_mem_print_bin("Certificate Pubkey", pubkey, pubkeyl);
    if(CompareMem(key_pair.q.value,  pubkey, pubkeyl) != 0) {
        eprint("CA public key verify fail");
        ret = SBCINVPARAM;
        goto errdone;
    }

    sbc_err_sysprn(SBC_LOG_CMN_PRIO_ERR, 2, 
           L"SBC", 
           L"FSBL", 
           L"Weapon System", 
           1, 
           L"EVT", 
           L"Device ID Verify Done");    
    

errdone:
    if (ret != SBCOK) {
      sbc_err_sysprn(SBC_LOG_CMN_PRIO_ERR, 2, 
             L"SBC", 
             L"FSBL", 
             L"Weapon System", 
             1, 
             L"EVT", 
             L"Device ID Verify Fail");
    }
    return ret;

}

SBCStatus SBC_BaseAnswerEncryptStore(VOID *blkhnd, UINT8* msg, UINT32 msgl, UINT8 *key, UINT32 keyl)
{
    SBCStatus ret = SBCOK;
    base_ansid_t ansid;

    SBC_AESContext aesctx;
    SBC_AESGcmCtx  ctx;


    ZeroMem((void *)&ansid ,sizeof ansid);
    CopyMem((void *)ansid.key, key, BASE_ANS_KEY_STR);

    RandomBytes((void *)ansid.iv, BASE_ANS_IV_KEY_STR); // Initial Vector 


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
            sbc_err_sysprn(SBC_LOG_CMN_PRIO_ERR, 2, 
                     L"SBC", 
                     L"FSBL", 
                     L"Weapon System", 
                     4, 
                     L"EVT", 
                     L"Base Answer Encrypt error");
      goto errdone;
    }

    ansid.msglen = ctx.out.length;
    
//  dprint("B-Ansr Message Len : %d", ansid.msglen);
//  SBC_external_mem_print_bin("B-Ansr Message", ansid.encmsg, ansid.msglen);
//  SBC_external_mem_print_bin("B-Ansr IV", ansid.iv, BASE_ANS_IV_KEY_STR);
//  SBC_external_mem_print_bin("B-Ansr Tag", ansid.tag, BASE_ANS_TAG_LEN);
//  SBC_external_mem_print_bin("B-Ansr Key", ansid.key, BASE_ANS_KEY_STR);



    ret = _baseanswer_store(blkhnd, (VOID *)&ansid);
    if (ret != SBCOK) {
      sbc_err_sysprn(SBC_LOG_CMN_PRIO_ERR, 2, 
                     L"SBC", 
                     L"FSBL", 
                     L"Weapon System", 
                     4, 
                     L"EVT", 
                     L"Base Answer Storing error");
      goto errdone;
    }


    ret = SBCOK;
errdone:

    if (msg != NULL) {
      FreePool(msg);
    }

    return ret;

}



SBCStatus  SBC_BaseAnswerValidate(VOID *blkhnd, UINT8 *answer, UINTN answerl, UINT8 *key, UINTN keylen)
{
    SBCStatus ret = SBCOK;
    //UINT8 rdbuf[256];
    //UINT8 baseanswer[256] = {0, };
    base_ansid_t ansid;
    SBC_AESContext aesctx;
    SBC_AESGcmCtx  ctx;

    UINT8 decbuf[BASE_ANS_STREAM_LEN] = {0,};

    SBC_RET_VALIDATE_ERRCODEMSG((answer != NULL), SBCNULLP, "Answer is Nill");


    // Read the Base Answer from Disk 

    ZeroMem((void *)&ctx, sizeof ctx);
    ZeroMem((void *)&aesctx, sizeof aesctx);
    ZeroMem(&ansid, sizeof ansid);

    ret = _baseanswer_extract_from_disk(blkhnd, &ansid);
    SBC_RET_VALIDATE_ERRCODEMSG((ret == SBCOK),ret, "Disk read fail");



    ctx.key.value = key;
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

    if (SBC_AESGcmDecrypt(&aesctx) != SBCOK) {
      Print(L"Base Answer Decrypt fail \n");
      ret = SBCFAIL;
      goto errdone;
    }

//  SBC_mem_print_bin("plain msg", answer, answerl);
//  SBC_mem_print_bin("decrypt msg", decbuf, ctx.out.length);

    if (CompareMem((const void *)decbuf, (const void *)answer, answerl) != 0) {
      Print(L"Base Answer validate Fail \n");
      ret = SBCFAIL;
      goto errdone;
    }

    Print(L"Base Answer validate Success \n");



errdone:
    return ret;

}

SBCStatus  SBC_SSBL_Verify(VOID *blkhnd, VOID *ansr, UINTN bank_id)
{
    SBCStatus       ret = SBCOK;
    [[maybe_unused]] EFI_STATUS      retval = EFI_SUCCESS;
    [[gnu::unused]] EFI_HANDLE      *hndl = NULL;
    [[gnu::unused]] UINT16          *fblpath = L"\\EFI\\rocky\\SSBL.efi";
    UINT8           *infostart = NULL;
    UINT32          last_of_fsbl = 0;
    UINT32          bsinfolen = 0;
    fsbl_bsinfo_t   bsinfo; 
    UINT32          bsptrcnt = 0;
    UINT8           HashValue[256];
    UINT32          HashSize =0;
    UINT32          fsbl_len =0;
    VOID            *EcPubKey = NULL;
    [[maybe_unused]] UINTN           HandleCount;

    LV_t            rdlv = {
            .length = 0,
            .value = NULL
      };



    ret = SBC_LoadSSBLImage(blkhnd, bank_id, &rdlv);
    SBC_RET_VALIDATE_ERRCODEMSG((ret == SBCOK), ret, "SSBL Image load fail");
    
    last_of_fsbl = rdlv.length - FSBL_BNIFO_SIZE;
    infostart = &((UINT8 *)rdlv.value)[last_of_fsbl];

    ZeroMem((void *)&bsinfo, sizeof bsinfo);
    CopyMem((void *)&bsinfo, (void *)infostart, sizeof bsinfo);

    ////SBC_external_mem_print_bin("BSINFO", (UINT8 *)&bsinfo, sizeof bsinfo);


    dprint("Signature Len     : %d", bsinfo.m.siglen );
    dprint("Firmware Info Len : %d", bsinfo.m.fwinfolen );
    dprint("Certificate Len   : %d", bsinfo.m.certlen );
    dprint("BaseAnswer Len    : %d", bsinfo.m.banswlen );
    dprint("BSinfo verdion    : %d", bsinfo.m.bsinfv );
    dprint("Spec.1 Value      : %d", bsinfo.m.reserv1 );
    dprint("Spec.2 Value      : %d", bsinfo.m.reserv2 );

    bsinfolen = bsinfo.m.siglen + bsinfo.m.fwinfolen + bsinfo.m.certlen  + bsinfo.m.banswlen;

      
    fsbl_len = last_of_fsbl = rdlv.length - FSBL_BNIFO_SIZE - bsinfolen;
    infostart = &((UINT8 *)rdlv.value)[last_of_fsbl];

    //dprint("FSBL Last : %d", last_of_fsbl);
    ////SBC_external_mem_print_bin("Addtional Information", infostart,bsinfolen  );

    fsbl_bsinfo_ptr_t info = {NULL, NULL, NULL, NULL};

    info.baseansw = (VOID *)&infostart[bsptrcnt];
    bsptrcnt += bsinfo.m.banswlen;

    //SBC_external_mem_print_bin("Base Answer", (UINT8 *)info.baseansw,  bsinfo.m.banswlen );

    info.fwinfo = (VOID *)&infostart[bsptrcnt];
    bsptrcnt += bsinfo.m.fwinfolen;

    //SBC_external_mem_print_bin("FW Info", (UINT8 *)info.fwinfo,  bsinfo.m.fwinfolen );

    info.certi = (VOID *)&infostart[bsptrcnt];
    bsptrcnt += bsinfo.m.certlen;

    //SBC_external_mem_print_bin("Certificate", (UINT8 *)info.certi,  bsinfo.m.certlen );

    info.signature = (VOID *)&infostart[bsptrcnt];
    bsptrcnt += bsinfo.m.siglen;

    //SBC_external_mem_print_bin("Signature", (UINT8 *)info.signature,  bsinfo.m.siglen );

    BOOLEAN retbool = TRUE;
    retbool = EcGetPublicKeyFromX509((CONST UINT8  *)info.certi, (UINTN)bsinfo.m.certlen,  &EcPubKey);
    if (retbool != TRUE) {
      eprint("EcGetPublicKeyFromX509 fail");
      ret = SBCFAIL;
      goto errdone;
    }

    dprint("FSBL image len : %d", fsbl_len);
    ret = SBC_HashCompute(
                         NULL, /* Not yet used */
                         rdlv.value,
                         fsbl_len,
                         HashValue
                      ) ; 


    HashSize = 32;

    retbool = EcDsaVerify(
        EcPubKey,
        CRYPTO_NID_SHA256,
        HashValue,
        HashSize,
        info.signature,
        bsinfo.m.siglen
        );

    if (retbool != TRUE) {
      eprint("FSBL Verify fail");
      ret = SBCFAIL;
      goto errdone;
    }

    sbc_err_sysprn(SBC_LOG_CMN_PRIO_INFO, 2, L"SBC", L"FSBL", L"CSC-01", 23, L"VERIFY", L"FSBL Integrate check is Done\n");
    Print(L"FSBL Verify Success !!!\n");

    ((LV_t *)ansr)->value = AllocateZeroPool(bsinfo.m.banswlen);
    if (((LV_t *)ansr)->value == NULL) {
      //sbc_err_sysprn(SBC_LOG_CMN_PRIO_INFO, 2, L"SBC", L"FSBL", L"CSC-01", 23, L"VERIFY", L"FSBL Integrate check is Done\n");
      eprint("Base Answer buffer allocate fail");
      ret = SBCNULLP;
      goto errdone;
    }

    ((LV_t *)ansr)->length = bsinfo.m.banswlen;
    CopyMem(((LV_t *)ansr)->value, info.baseansw, bsinfo.m.banswlen);

//    switch (bootmode) {
//    case BOOT_MODE_FACTORY:
//      break;
//    default:
//      // Base Answer Validate
//      ret = SBC_BaseAnswerValidate(blkhnd, (UINT8 *)info.baseansw, bsinfo.m.banswlen );
////    switch (ret) {
////    case SBCBSANSWNOTFND:
////      ((LV_t *)ansr)->value = AllocateZeroPool(bsinfo.m.banswlen);
////      if (((LV_t *)ansr)->value == NULL) {
////        ret = SBCNULLP;
////        Print(L"Base Answer object create fail \n");
////        goto errdone;
////      }
////      CopyMem(((LV_t *)ansr)->value, info.baseansw, bsinfo.m.banswlen);
////      //goto errdone;
////      break;
////    case SBCOK:
////      break;
////    default:
////      goto errdone;
////      break;
////    }
//      break;
//    }






    //ret = SBCOK;

errdone:

    if (EcPubKey != NULL) {
      EcFree(EcPubKey);
    }
    if (rdlv.value != NULL) {
      FreePool(rdlv.value);
      rdlv.value = NULL;

    }
    return ret;

}



SBCStatus  SBC_FSBL_Verify(VOID *blkhnd, VOID *ansr)
{
    SBCStatus       ret = SBCOK;
    EFI_STATUS      retval = EFI_SUCCESS;
    EFI_HANDLE      *hndl = NULL;
    UINT16          *fblpath = L"\\EFI\\rocky\\FSBL.efi";
    UINT8           *infostart = NULL;
    UINT32          last_of_fsbl = 0;
    UINT32          bsinfolen = 0;
    fsbl_bsinfo_t   bsinfo; 
    UINT32          bsptrcnt = 0;
    UINT8           HashValue[256];
    UINT32          HashSize =0;
    UINT32          fsbl_len =0;
    VOID            *EcPubKey = NULL;
    UINTN           HandleCount;

    LV_t            rdlv = {
            .length = 0,
            .value = NULL
      };

    HandleCount  = SBC_FindEfiFileSystemProtocol(&hndl);

    ret = SBC_GetFileSize(fblpath, (UINTN *)&rdlv.length);
    if (ret != SBCOK) {
      goto errdone;
    }

    rdlv.value = AllocateZeroPool((UINTN)rdlv.length);
    if (rdlv.value == NULL) {
      eprint("FSBL Verify Allocate Pool fail");
      ret = SBCNULLP;
      goto errdone;
    }

    retval = SBC_ReadFile(hndl[HandleCount - 1], fblpath, &rdlv);
    if (EFI_ERROR(retval)) {
      eprint("%s filr read fail : %r", fblpath, retval);
      ret = SBCIO;
      goto errdone;
    }

    last_of_fsbl = rdlv.length - FSBL_BNIFO_SIZE;
    infostart = &((UINT8 *)rdlv.value)[last_of_fsbl];

    ZeroMem((void *)&bsinfo, sizeof bsinfo);

    CopyMem((void *)&bsinfo, (void *)infostart, sizeof bsinfo);

    ////SBC_external_mem_print_bin("BSINFO", (UINT8 *)&bsinfo, sizeof bsinfo);


    dprint("Signature Len     : %d", bsinfo.m.siglen );
    dprint("Firmware Info Len : %d", bsinfo.m.fwinfolen );
    dprint("Certificate Len   : %d", bsinfo.m.certlen );
    dprint("BaseAnswer Len    : %d", bsinfo.m.banswlen );
    dprint("BSinfo verdion    : %d", bsinfo.m.bsinfv );
    dprint("Spec.1 Value      : %d", bsinfo.m.reserv1 );
    dprint("Spec.2 Value      : %d", bsinfo.m.reserv2 );

    bsinfolen = bsinfo.m.siglen + bsinfo.m.fwinfolen + bsinfo.m.certlen  + bsinfo.m.banswlen;

      
    fsbl_len = last_of_fsbl = rdlv.length - FSBL_BNIFO_SIZE - bsinfolen;
    infostart = &((UINT8 *)rdlv.value)[last_of_fsbl];

    //dprint("FSBL Last : %d", last_of_fsbl);
    ////SBC_external_mem_print_bin("Addtional Information", infostart,bsinfolen  );

    fsbl_bsinfo_ptr_t info = {NULL, NULL, NULL, NULL};

    info.baseansw = (VOID *)&infostart[bsptrcnt];
    bsptrcnt += bsinfo.m.banswlen;

    //SBC_external_mem_print_bin("Base Answer", (UINT8 *)info.baseansw,  bsinfo.m.banswlen );

    info.fwinfo = (VOID *)&infostart[bsptrcnt];
    bsptrcnt += bsinfo.m.fwinfolen;

    //SBC_external_mem_print_bin("FW Info", (UINT8 *)info.fwinfo,  bsinfo.m.fwinfolen );

    info.certi = (VOID *)&infostart[bsptrcnt];
    bsptrcnt += bsinfo.m.certlen;

    //SBC_external_mem_print_bin("Certificate", (UINT8 *)info.certi,  bsinfo.m.certlen );

    info.signature = (VOID *)&infostart[bsptrcnt];
    bsptrcnt += bsinfo.m.siglen;

    //SBC_external_mem_print_bin("Signature", (UINT8 *)info.signature,  bsinfo.m.siglen );

    BOOLEAN retbool = TRUE;
    retbool = EcGetPublicKeyFromX509((CONST UINT8  *)info.certi, (UINTN)bsinfo.m.certlen,  &EcPubKey);
    if (retbool != TRUE) {
      eprint("EcGetPublicKeyFromX509 fail");
      ret = SBCFAIL;
      goto errdone;
    }

    dprint("FSBL image len : %d", fsbl_len);
    ret = SBC_HashCompute(
                         NULL, /* Not yet used */
                         rdlv.value,
                         fsbl_len,
                         HashValue
                      ) ; 


    HashSize = 32;

    retbool = EcDsaVerify(
        EcPubKey,
        CRYPTO_NID_SHA256,
        HashValue,
        HashSize,
        info.signature,
        bsinfo.m.siglen
        );

    if (retbool != TRUE) {
      eprint("FSBL Verify fail");
      ret = SBCFAIL;
      goto errdone;
    }

    sbc_err_sysprn(SBC_LOG_CMN_PRIO_INFO, 2, L"SBC", L"FSBL", L"CSC-01", 23, L"VERIFY", L"FSBL Integrate check is Done\n");
    Print(L"FSBL Verify Success !!!\n");

    ((LV_t *)ansr)->value = AllocateZeroPool(bsinfo.m.banswlen);
    if (((LV_t *)ansr)->value == NULL) {
      //sbc_err_sysprn(SBC_LOG_CMN_PRIO_INFO, 2, L"SBC", L"FSBL", L"CSC-01", 23, L"VERIFY", L"FSBL Integrate check is Done\n");
      eprint("Base Answer buffer allocate fail");
      ret = SBCNULLP;
      goto errdone;
    }

    ((LV_t *)ansr)->length = bsinfo.m.banswlen;
    CopyMem(((LV_t *)ansr)->value, info.baseansw, bsinfo.m.banswlen);

//    switch (bootmode) {
//    case BOOT_MODE_FACTORY:
//      break;
//    default:
//      // Base Answer Validate
//      ret = SBC_BaseAnswerValidate(blkhnd, (UINT8 *)info.baseansw, bsinfo.m.banswlen );
////    switch (ret) {
////    case SBCBSANSWNOTFND:
////      ((LV_t *)ansr)->value = AllocateZeroPool(bsinfo.m.banswlen);
////      if (((LV_t *)ansr)->value == NULL) {
////        ret = SBCNULLP;
////        Print(L"Base Answer object create fail \n");
////        goto errdone;
////      }
////      CopyMem(((LV_t *)ansr)->value, info.baseansw, bsinfo.m.banswlen);
////      //goto errdone;
////      break;
////    case SBCOK:
////      break;
////    default:
////      goto errdone;
////      break;
////    }
//      break;
//    }






    //ret = SBCOK;

errdone:

    if (EcPubKey != NULL) {
      EcFree(EcPubKey);
    }
    if (rdlv.value != NULL) {
      FreePool(rdlv.value);
      rdlv.value = NULL;

    }
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

    UINT8 devidhsah[SBC_AT_HASH_LEN] = {0,};

    SBC_RET_VALIDATE_ERRCODEMSG((devid != NULL),SBCNULLP, "Out buffer Nill");

   


    // TODO : read the device information 
    ZeroMem((void *)&info, sizeof info);


    _baseboard_sn(&info);
//  SBC_external_mem_print_bin("BaseBoard SN", info.mbsn,info.mbsnl);
//  SBC_mem_print_bin("BaseBoard SN", info.mbsn,info.mbsnl);

    _memorydevice_sn(&info);
//  SBC_external_mem_print_bin("MemoryDevice SN", info.mmsn, info.mmsnl);
//  SBC_mem_print_bin("MemoryDevice SN", info.mmsn, info.mmsnl);

    _nvme_get_serial(&info);
//  SBC_external_mem_print_bin("NVME SN", info.nvmesn,info.nvmesnl);
//  SBC_mem_print_bin("NVME SN", info.nvmesn,info.nvmesnl);

    //_read_fsbl_image(&rdlv);
    efi_boot_fsbl_load(&rdlv);
    SBC_RET_VALIDATE_ERRCODEMSG((rdlv.value != NULL), SBCNULLP, "FSBL read fail");

    ret = SBC_HashCompute(
                         NULL, /* Not yet used */
                         rdlv.value,
                         rdlv.length,
                         devidhsah
                      ) ; 

    if (ret != SBCOK) {
      eprint("FSBL Hash compute fail \n");
      goto errdone;
    }


    rdlv.length = SBC_AT_HASH_LEN;

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

    if (ret != SBCOK) {
      eprint("Device Dice Message Hash compute fail \n");
      goto errdone;
    }

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

SBCStatus  SBC_GenMigrationKey(VOID *priv, UINT32 currbankid, UINT32 prevbankid, VOID *out)
{
  //Migration Key = H(H(Unique HW ID)||H(Current FSBL)||H(Current SSBL)||H(Current KERNEL)||H(Newer SSBL)||H(Newer KERNEL))
    SBCStatus ret = SBCOK;
    UINTN integcnt = 0;
    UINTN migkeycnt = 0;
//  mig_key_t *key = NULL;

    UINT8 *migkey_hash = NULL;

    hw_uniqueinfo_t info;
    UINT8 *integbuf = NULL; // Integration bufefr
    UINTN startaddr = 0;
    UINTN startlba = 0;
    UINTN imglen = 0;
    boot_fw_inf_t *fwinf;

    dprint("Migration Key creation startnig !!!");

    SBC_RET_VALIDATE_ERRCODEMSG((priv != NULL), SBCNULLP, "Invalid Parameter");

    ZeroMem((void *)&info, sizeof info);

    // Step 1. Compute the HW ID 
    _baseboard_sn(&info);
    _memorydevice_sn(&info);
    _nvme_get_serial(&info);

    fwinf = AllocatePool(sizeof(boot_fw_inf_t));
    SBC_RET_VALIDATE_ERRCODEMSG((fwinf != NULL),SBCNULLP, "Firmware Info Memory allocate Nill");

    integbuf = AllocatePool(info.mbsnl + info.mmsnl + info.nvmesnl);
    SBC_RET_VALIDATE_ERRCODEMSG((integbuf != NULL),SBCNULLP, "HW Info Compute buffer Nill");

    integcnt = 0;
    CopyMem((void *)&integbuf[0], info.mbsn, info.mbsnl);
    integcnt = info.mbsnl;

    //Print(L"Next cnt : %d \n", cnt);
    CopyMem((void *)&integbuf[integcnt], info.mmsn, info.mmsnl);
    integcnt += info.mmsnl;

    //Print(L"Next Next cnt : %d \n", cnt);
    CopyMem((void *)&integbuf[integcnt], info.nvmesn, info.nvmesnl);
    integcnt += info.nvmesnl;

    migkey_hash = AllocatePool(SBC_AT_HASH_LEN * 6);
    SBC_RET_VALIDATE_ERRCODEMSG((migkey_hash != NULL),SBCNULLP, "MigKEy Compute buffer Nill");
    migkeycnt = 0;

    ret = SBC_HashCompute(
                             NULL, /* Not yet used */
                             integbuf,
                             integcnt,
                             &migkey_hash[migkeycnt]
                          ) ;

    if (ret != SBCOK) {
      eprint("Device Dice Message Hash compute fail \n");
      goto errdone;
    }

    migkeycnt +=  SBC_AT_HASH_LEN;

    //Step 2. Read Current Image and Hash compute
    startaddr = (BOOT_SECTOR1_OFS | (BOOT_FW_IMGMAX *  (currbankid - 1)));
    startlba = (startaddr >> SBC_RAWPRT_DFLT_SHIFT);
    imglen = ALIGN_VALUE(sizeof *fwinf, SBC_RAWPRT_DFLT_BLK_SZ);

    
    ret = SBC_RawPrtReadBlock(priv, (void *)fwinf->value, (UINT32 *)&imglen, startlba);
    SBC_RET_VALIDATE_ERRCODEMSG((ret == SBCOK), ret, "Raw Partition read fail");

    // Hash compute
    
    ret = SBC_HashCompute(NULL, fwinf->mbr.fsblimg, fwinf->mbr.fsbln, &migkey_hash[migkeycnt]);
    SBC_RET_VALIDATE_ERRCODEMSG((ret == SBCOK), ret, "Hash Compue fail");
    migkeycnt +=  SBC_AT_HASH_LEN;

    ret = SBC_HashCompute(NULL, fwinf->mbr.ssblimg, fwinf->mbr.ssbln,  &migkey_hash[migkeycnt]);
    SBC_RET_VALIDATE_ERRCODEMSG((ret == SBCOK), ret, "Hash Compue fail");
    migkeycnt +=  SBC_AT_HASH_LEN;

    ret = SBC_HashCompute(NULL, fwinf->mbr.osimg, fwinf->mbr.osln,  &migkey_hash[migkeycnt]);
    SBC_RET_VALIDATE_ERRCODEMSG((ret == SBCOK), ret, "Hash Compue fail");
    migkeycnt +=  SBC_AT_HASH_LEN;

    // Step 3. Read the New Image and hash compute

    ZeroMem(fwinf->value, sizeof fwinf);
    startaddr = (BOOT_SECTOR1_OFS | (BOOT_FW_IMGMAX *  (prevbankid - 1)));
    startlba = (startaddr >> SBC_RAWPRT_DFLT_SHIFT);
    imglen = ALIGN_VALUE(sizeof fwinf, SBC_RAWPRT_DFLT_BLK_SZ);

    ret = SBC_RawPrtReadBlock(priv, (void *)fwinf->value, (UINT32 *)&imglen, startlba);
    SBC_RET_VALIDATE_ERRCODEMSG((ret == SBCOK), ret, "Raw Partition read fail");

    ret = SBC_HashCompute(NULL, fwinf->mbr.ssblimg, fwinf->mbr.ssbln,  &migkey_hash[migkeycnt]);
    SBC_RET_VALIDATE_ERRCODEMSG((ret == SBCOK), ret, "Hash Compue fail");
    migkeycnt +=  SBC_AT_HASH_LEN;

    ret = SBC_HashCompute(NULL, fwinf->mbr.osimg, fwinf->mbr.osln,  &migkey_hash[migkeycnt]);
    SBC_RET_VALIDATE_ERRCODEMSG((ret == SBCOK), ret, "Hash Compue fail");
    migkeycnt +=  SBC_AT_HASH_LEN;


    ret = SBC_HashCompute(NULL, migkey_hash, migkeycnt,  (UINT8 *)out);
    SBC_RET_VALIDATE_ERRCODEMSG((ret == SBCOK), ret, "Hash Compue fail");

    
    

errdone:
    if (integbuf != NULL) {
        FreePool(integbuf);
    }

    if (migkey_hash != NULL) {
        FreePool(migkey_hash);
    }

    if (fwinf != NULL) {
      FreePool(fwinf);
    }

    return ret;

}

// FSBL Integrity check 
SBCStatus  SBC_FSBLIntgCheck(EFI_HANDLE *h_image , VOID *blkio)
{
    SBCStatus ret = SBCOK;

    UINT8 rdbuf[SBC_BLKDEV_BLKSZ << 2] = {0,};
    UINT32 rdlen = 532 + 529;
//  VOID *blkio;
    UINTN calen = 0;
    UINTN certlen = 0;

//  ret = SBC_FindBlkIoHandle(&blkio);
//  if (ret != SBCOK) {
//    Print(L"Find Block I/O handle fail \n");
//    goto errdone;
//  }


    rdlen = SBC_BLKDEV_BLKSZ;
    ret = SBC_RawPrtReadBlock(blkio, rdbuf, &rdlen, SBC_INTG_BLOCK_LAB);
    if (ret != SBCOK) {
      Print(L"Raw Partition Read behavior fail \n");
      goto errdone;
    }

    rdlen = SBC_BLKDEV_BLKSZ;
    ret = SBC_RawPrtReadBlock(blkio, &rdbuf[rdlen], &rdlen, SBC_INTG_BLOCK_LAB + 1);
    if (ret != SBCOK) {
      Print(L"Raw Partition Read behavior fail \n");
      goto errdone;
    }

    rdlen = SBC_BLKDEV_BLKSZ;
    ret = SBC_RawPrtReadBlock(blkio, &rdbuf[rdlen*2], &rdlen, SBC_INTG_BLOCK_LAB + 2);
    if (ret != SBCOK) {
      Print(L"Raw Partition Read behavior fail \n");
      goto errdone;
    }
    // TO DO : certificatoin lengt read, and than, SHOULD be check  whether read more the data from device 
    // At the June 10,  fixed it ( as follows : ROOT CA -c> 532 , Intermidnate CA -> 529 

    //SBC_mem_print_bin("cRT", &rdbuf[SBC_INTG_CRET_SKIP], 532 + 529);
    certlen = calen = 532;
    ret = SBC_X509VerifyCert(
                      (CONST UINT8 *)&rdbuf[SBC_INTG_CRET_SKIP],  // CA Cert
                      calen,
                      (CONST UINT8 *)&rdbuf[SBC_INTG_CRET_SKIP], // Signed Cert
                      certlen

        );

    if (ret != SBCOK) {
      int_eprint("FSBL Verify fail \n");
      goto errdone;
    }


    intgreen_dprint("!!! FSBL Integrity Check Success !!!");

    calen = 532;
    certlen =  529;

   
   // SBC_mem_print_bin("Int cRT", &rdbuf[SBC_INTG_CRET_SKIP + calen], 529);
    ret = SBC_X509VerifyCert(
                      (CONST UINT8 *)&rdbuf[SBC_INTG_CRET_SKIP + calen],
                      certlen,
                      (CONST UINT8 *)&rdbuf[SBC_INTG_CRET_SKIP],
                      calen

        );

    
    if (ret != SBCOK) {
      int_eprint("SSBL Verify fail ^^ \n");
      goto errdone;
    }

    intgreen_dprint("SSBL Integrity Check Success !!!");

    ret = SBCOK;

    

errdone:
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

