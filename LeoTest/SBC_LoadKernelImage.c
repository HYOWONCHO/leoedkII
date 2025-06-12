
#include <Uefi.h>
#include <Library/UefiBootServicesTableLib.h>
#include <Library/UefiRuntimeServicesTableLib.h>
#include <Library/UefiLib.h>
#include <Library/MemoryAllocationLib.h>
#include <Library/DevicePathLib.h>
#include <Library/DebugLib.h>
#include <Library/BaseLib.h> // For StrLen, StrCpy, ZeroMem

// Protocols
#include <Protocol/LoadedImage.h>
#include <Protocol/SimpleFileSystem.h>
#include <Protocol/BlockIo.h>
#include <Protocol/DevicePathToText.h>

#include <Guid/FileInfo.h>
#include <Library/BaseMemoryLib.h>
#include <string.h>

#include <IndustryStandard/PeImage.h>

#ifndef uefi_call_wrapper
#define uefi_call_wrapper(Function, nargs, ...) \
  ((EFI_STATUS) ((Function)(__VA_ARGS__)))
#endif

//
//// Define minimal structures if not already provided.
//typedef struct {
//  UINT8  e_ident[16];
//  UINT16 e_type;
//  UINT16 e_machine;
//  UINT32 e_version;
//  UINT64 e_entry;    // Entry point address
//  // ... other fields omitted for brevity
//} Elf64_Ehdr;
//
//VOID *
//ComputeKernelEntry(
//  IN VOID  *KernelBase
//  )
//{
//  VOID *KernelEntry = NULL;
//
//  // First, try to interpret the image as a PE/COFF file.
//  EFI_IMAGE_DOS_HEADER *DosHdr = (EFI_IMAGE_DOS_HEADER *)KernelBase;
//  if (DosHdr->e_magic == EFI_IMAGE_DOS_SIGNATURE) {
//    EFI_IMAGE_NT_HEADERS *NtHdr
//      = (EFI_IMAGE_NT_HEADERS *)((UINT8 *)KernelBase + DosHdr->e_lfanew);
//    if (NtHdr->Signature == EFI_IMAGE_NT_SIGNATURE) {
//      // For PE/COFF: Entry point = Base address + Relative Address of Entry Point.
//      KernelEntry = (VOID *)((UINT8 *)KernelBase +
//                    NtHdr->OptionalHeader.AddressOfEntryPoint);
//      DEBUG((DEBUG_INFO, "PE/COFF: Kernel entry point computed at %p\n", KernelEntry));
//      return KernelEntry;
//    }
//  }
//
//  // If not PE/COFF, try to interpret as an ELF image (64-bit in this example).
//  Elf64_Ehdr *ElfHdr = (Elf64_Ehdr *)KernelBase;
//  if (ElfHdr->e_ident[0] == 0x7F &&
//      ElfHdr->e_ident[1] == 'E' &&
//      ElfHdr->e_ident[2] == 'L' &&
//      ElfHdr->e_ident[3] == 'F') {
//    // For ELF: Entry point is directly provided by e_entry.
//    KernelEntry = (VOID *)(UINTN)ElfHdr->e_entry;
//    DEBUG((DEBUG_INFO, "ELF: Kernel entry point computed at %p\n", KernelEntry));
//    return KernelEntry;
//  }
//
//  // If the image format is not recognized, kernel entry remains NULL.
//  DEBUG((DEBUG_ERROR, "Unrecognized kernel image format.\n"));
//  return NULL;
//}
//
//EFI_STATUS  LoadKernelImage(EFI_HANDLE ImageHandle, EFI_SYSTEM_TABLE *SystemTable) {
//    EFI_STATUS Status;
//    UINTN MemoryMapSize = 0;
//    EFI_MEMORY_DESCRIPTOR *MemoryMap = NULL;
//    UINTN MapKey;
//    UINTN DescriptorSize;
//    UINT32 DescriptorVersion;
//
//    VOID(*KernelEntry)(VOID) = (VOID *)0x100000; // Example kernel entry address
//    // Initialize the EFI library
//    //InitializeLib(ImageHandle, SystemTable);
//
//    // Step 1: Get the size of the memory map. The first call will fail with
//    // EFI_BUFFER_TOO_SMALL, but it tells us how large a buffer we need.
//    Status = uefi_call_wrapper(SystemTable->BootServices->GetMemoryMap, 5,
//             &MemoryMapSize, MemoryMap, &MapKey, &DescriptorSize, &DescriptorVersion);
//
////  Status = SystemTable->BootServices->GetMemoryMap(
////           &MemoryMapSize, MemoryMap, &MapKey, &DescriptorSize, &DescriptorVersion);
//    if (Status != EFI_BUFFER_TOO_SMALL) {
//        Print(L"Unexpected error when getting memory map size: %r\n", Status);
//        return Status;
//    }
//
//    // Step 2: Allocate a buffer large enough for the memory map.
//    MemoryMap = AllocatePool(MemoryMapSize);
//    if (MemoryMap == NULL) {
//        Print(L"Failed to allocate memory for the memory map.\n");
//        return EFI_OUT_OF_RESOURCES;
//    }
//
//    // Step 3: Get the complete memory map.
//    Status = SystemTable->BootServices->GetMemoryMap(
//             &MemoryMapSize, MemoryMap, &MapKey, &DescriptorSize, &DescriptorVersion);
//    if (EFI_ERROR(Status)) {
//        Print(L"Error retrieving memory map: %r\n", Status);
//        FreePool(MemoryMap);
//        return Status;
//    }
//
//    // Step 4: Call ExitBootServices
//    //
//    // The MapKey must be the one obtained in the GetMemoryMap call.
//    //Status = uefi_call_wrapper(SystemTable->BootServices->ExitBootServices, 2, ImageHandle, MapKey);
//
//    Status = SystemTable->BootServices->ExitBootServices(ImageHandle, MapKey);
//    if (EFI_ERROR(Status)) {
//        Print(L"ExitBootServices failed: %r\n", Status);
//        FreePool(MemoryMap);
//        return Status;
//    }
//
//    // At this point, UEFI Boot Services are no longer available.
//    // Do any post-exit boot tasks here. For example, you might jump to your OS kernel.
//
//    //
//    // For demonstration, we'll directly write to video memory (typical for text mode)
//    // to display a simple message. Note that since we no longer have UEFI services,
//    // functions like Print() will not work.
//    //
////  volatile CHAR16 *VideoMemory = (volatile CHAR16 *)0xB8000; // VGA text mode base
////  VideoMemory[0] = L'H';
////  VideoMemory[1] = 0x07; // light grey on black background
////  VideoMemory[2] = L'i';
////  VideoMemory[3] = 0x07;
//
//    // If this were a bootloader that hands off to an OS kernel, you
//    // would jump to the kernel's entry point here (and not return).
//
//    // For safety, this example simply sits here (or you could enter an infinite loop).
//    KernelEntry();
//    return EFI_SUCCESS; // Never reached
//}


//
EFI_STATUS
LoadKernelFile (
  IN EFI_HANDLE         ImageHandle,
  IN EFI_SYSTEM_TABLE   *SystemTable,
  OUT VOID              **KernelBufferOut,
  OUT UINTN             *KernelSizeOut
  )
{
  EFI_STATUS                     Status;
  EFI_SIMPLE_FILE_SYSTEM_PROTOCOL *SimpleFs;
  EFI_FILE_PROTOCOL              *Root;
  EFI_FILE_PROTOCOL              *KernelFile;
  EFI_FILE_INFO                  *FileInfo;
  UINTN                          FileInfoSize = 0;
  VOID                           *KernelBuffer = NULL;
  UINTN                          KernelFileSize = 0;
  EFI_HANDLE                      *handle;
  UINTN                           hndlcnt;


  Status = SystemTable->BootServices->LocateHandleBuffer(
                      ByProtocol,
                      &gEfiSimpleFileSystemProtocolGuid,
                      NULL,
                      &hndlcnt,
                      &handle

      );

  if (EFI_ERROR(Status)) {
    Print(L"LocateHandleBuffer: %r\n", Status);
    return Status;
  }

  // 1. Locate the Simple File System Protocol on the device (assumed here as ImageHandle).
  Status = SystemTable->BootServices->HandleProtocol(
              *handle,
              &gEfiSimpleFileSystemProtocolGuid,
              (VOID **)&SimpleFs
            );
  if (EFI_ERROR(Status)) {
    Print(L"SystemTable->BootServices->HandleProtoco: %r\n", Status);
    return Status;
  }

  // 2. Open the root directory of the volume.
  Status = SimpleFs->OpenVolume(SimpleFs, &Root);
  if (EFI_ERROR(Status)) {
    Print(L"SimpleFs->OpenVolume: %r\n", Status);
    return Status;
  }

  // 3. Open the kernel file (modify the path as required).
  Status = Root->Open(Root, &KernelFile, L"\\EFI\\rocky\\grubx64.efi", EFI_FILE_MODE_READ, 0);
  if (EFI_ERROR(Status)) {
    Print(L"Root->Open(: %r\n", Status);
    return Status;
  }

  // 4. Get the file size by using GetInfo() with EFI_FILE_INFO.
  FileInfoSize = 0;
  Status = KernelFile->GetInfo(KernelFile, &gEfiFileInfoGuid, &FileInfoSize, NULL);
  if (Status != EFI_BUFFER_TOO_SMALL) {
    Print(L"KernelFile->GetInfo: %r\n", Status);
    KernelFile->Close(KernelFile);
    return Status;
  }

  Status = SystemTable->BootServices->AllocatePool(EfiLoaderData, FileInfoSize, (VOID **)&FileInfo);
  if (EFI_ERROR(Status)) {
    Print(L"ystemTable->BootServices->AllocatePoolle: %r\n", Status);
    KernelFile->Close(KernelFile);
    return Status;
  }

  Status = KernelFile->GetInfo(KernelFile, &gEfiFileInfoGuid, &FileInfoSize, FileInfo);
  if (EFI_ERROR(Status)) {
    Print(L"FKernelFile->GetInfo: %r\n", Status);
    SystemTable->BootServices->FreePool(FileInfo);
    KernelFile->Close(KernelFile);
    return Status;
  }

  KernelFileSize = (UINTN) FileInfo->FileSize;
  gBS->FreePool(FileInfo);

  // 5. Allocate memory for the kernel image and read the file.
  Status = SystemTable->BootServices->AllocatePool(EfiLoaderData, KernelFileSize, &KernelBuffer);
  if (EFI_ERROR(Status)) {
    Print(L"SystemTable->BootServices->AllocatePool: %r\n", Status);
    KernelFile->Close(KernelFile);
    return Status;
  }

  Status = KernelFile->Read(KernelFile, &KernelFileSize, KernelBuffer);
  KernelFile->Close(KernelFile);
  if (EFI_ERROR(Status)) {
    Print(L"KernelFile->Read: %r\n", Status);
    SystemTable->BootServices->FreePool(KernelBuffer);
    return Status;
  }

  // 6. Return the loaded kernel buffer and its size.
  *KernelBufferOut = KernelBuffer;
  *KernelSizeOut = KernelFileSize;
  return EFI_SUCCESS;
}
//
EFI_STATUS
LoadKernelImage (
  IN EFI_HANDLE        ImageHandle,
  IN EFI_SYSTEM_TABLE  *SystemTable
  )
{
  EFI_STATUS Status;
  VOID       *KernelBuffer = NULL;
  UINTN      KernelSize = 0;
  VOID       *KernelEntry = NULL;
  UINTN      MemoryMapSize = 0;
  EFI_MEMORY_DESCRIPTOR *MemoryMap = NULL;
  UINTN      MapKey, DescriptorSize;
  UINT32     DescriptorVersion;

  //
  // Step 1: Load the kernel file into memory
  //
  Status = LoadKernelFile(ImageHandle, SystemTable, &KernelBuffer, &KernelSize);
  if (EFI_ERROR(Status)) {
    DEBUG((DEBUG_ERROR, "Failed to load kernel file: %r\n", Status));
    Print(L"%a:%d Failed to load kernel file: %r\n", __FUNCTION__, __LINE__, Status);
    return Status;
  }

  //
  // Step 2: Parse the kernel header for the entry point.
  // Try PE/COFF first (commonly used in Windows-like environments).
  //
  {
    // Note: The below code assumes the image starts with an EFI_IMAGE_DOS_HEADER.
    // For PE/COFF images as defined in UEFI, the DOS header is usually minimal.
    EFI_IMAGE_DOS_HEADER *DosHdr = (EFI_IMAGE_DOS_HEADER *)KernelBuffer;
    if (DosHdr->e_magic == EFI_IMAGE_DOS_SIGNATURE) {
      EFI_IMAGE_NT_HEADERS64 *NtHdr = (EFI_IMAGE_NT_HEADERS64 *)((UINT8*)KernelBuffer + DosHdr->e_lfanew);
      if (NtHdr->Signature == EFI_IMAGE_NT_SIGNATURE) {
        // Calculate the entry point from the image base plus the AddressOfEntryPoint.
        KernelEntry = (VOID *)((UINT8 *)KernelBuffer + NtHdr->OptionalHeader.AddressOfEntryPoint);
        DEBUG((DEBUG_INFO, "Kernel PE/COFF entry point at %p\n", KernelEntry));
        Print(L"Kernel PE/COFF entry point at %p\n", KernelEntry);
      }
    }
  }

  //
  // Step 3: If not PE/COFF, try interpreting the kernel as an ELF image.
  //
  if (KernelEntry == NULL) {
    // Define simple ELF header structures for demonstration.
    typedef struct {
      UINT8  e_ident[16];
      UINT16 e_type;
      UINT16 e_machine;
      UINT32 e_version;
      UINT64 e_entry;
      // ... rest omitted for brevity
    } Elf64_Ehdr;

    Elf64_Ehdr *ElfHdr = (Elf64_Ehdr *)KernelBuffer;
    // Check ELF magic number: 0x7F followed by "ELF"
    if (ElfHdr->e_ident[0] == 0x7F &&
        ElfHdr->e_ident[1] == 'E' &&
        ElfHdr->e_ident[2] == 'L' &&
        ElfHdr->e_ident[3] == 'F')
    {
      KernelEntry = (VOID *)(UINTN)ElfHdr->e_entry;
      Print(L"Kernel ELF entry point at %p\n", KernelEntry);
      DEBUG((DEBUG_INFO, "Kernel ELF entry point at %p\n", KernelEntry));
    }
  }

  if (KernelEntry == NULL) {
    DEBUG((DEBUG_ERROR, "Could not determine the kernel entry point\n"));
    Print(L"Could not determine the kernel entry point: %r\n", Status);
    return EFI_LOAD_ERROR;
  }

  //
  // Step 4: Prepare for kernel jump by obtaining a current memory map.
  //
  MemoryMapSize = 0;
  // First call to determine Memory Map size.
  Status = gBS->GetMemoryMap(&MemoryMapSize, MemoryMap, &MapKey, &DescriptorSize, &DescriptorVersion);
  if (Status != EFI_BUFFER_TOO_SMALL) {
    DEBUG((DEBUG_ERROR, "Unexpected error getting memory map size: %r\n", Status));
    Print(L"Unexpected error getting memory map size: %r\n", Status);
    return Status;
  }

  Print(L"(%s:%d)GetMemoryMap size : %d and MemoryMap %p\n", MemoryMapSize, MemoryMap);

  // Allocate buffer for the memory map.
  Status = gBS->AllocatePool(EfiLoaderData, MemoryMapSize, (VOID **)&MemoryMap);
  if (EFI_ERROR(Status)) {
    DEBUG((DEBUG_ERROR, "Failed to allocate pool for memory map: %r\n", Status));
    Print(L"Failed to allocate pool for memory map: %r\n", Status);
    return Status;
  }

  Print(L"(%s:%d)GetMemoryMap size : %d and MemoryMap %p\n", MemoryMapSize, MemoryMap);

  Status = gBS->GetMemoryMap(&MemoryMapSize, MemoryMap, &MapKey, &DescriptorSize, &DescriptorVersion);
  if (EFI_ERROR(Status)) {
    DEBUG((DEBUG_ERROR, "Failed to retrieve memory map: %r\n", Status));

    Print(L"Failed to retrieve memory map: %r\n", Status);
    return Status;
  }

  //
  // Step 5: Exit Boot Services to hand over control to the kernel.
  //
  Status = gBS->ExitBootServices(ImageHandle, MapKey);
  if (EFI_ERROR(Status)) {
    // Typically, you must re-read the memory map and try again if ExitBootServices fails.
    DEBUG((DEBUG_ERROR, "ExitBootServices error: %r\n", Status));
    Print(L"ExitBootServicese error: %r\n", Status);
    return Status;
  }

  //
  // Step 6: Jump to the kernel entry point.
  // Make sure any necessary CPU state or boot parameters are set up beforehand.
  //
  ((void (*) (VOID))KernelEntry)();

  // Should not return.
  return EFI_SUCCESS;
}
 #include <Protocol/DevicePathFromText.h> // Not directly needed with manual construction


// ... (KERNEL_ENTRY_POINT typedef and LocateSimpleFileSystem function remain the same) ...

// Define the kernel entry point signature.
typedef VOID (*KERNEL_ENTRY_POINT)(
  IN EFI_SYSTEM_TABLE  *SystemTable,
  IN EFI_MEMORY_DESCRIPTOR *MemoryMap,
  IN UINTN             MemoryMapSize,
  IN UINTN             DescriptorSize,
  IN VOID              *Reserved
  );


EFI_STATUS
LocateSimpleFileSystem (
  OUT EFI_SIMPLE_FILE_SYSTEM_PROTOCOL **Fs
  )
{
  EFI_STATUS  Status;
  UINTN       NumHandles;
  EFI_HANDLE  *HandleBuffer;
  UINTN       Index;

  Status = gBS->LocateHandleBuffer (
                  ByProtocol,
                  &gEfiSimpleFileSystemProtocolGuid,
                  NULL,
                  &NumHandles,
                  &HandleBuffer
                  );
  if (EFI_ERROR(Status)) {
    Print(L"LocateHandleBuffer(gEfiSimpleFileSystemProtocolGuid) failed: %r\n", Status);
    return Status;
  }

  for (Index = 0; Index < NumHandles; Index++) {
    Status = gBS->OpenProtocol (
                    HandleBuffer[Index],
                    &gEfiSimpleFileSystemProtocolGuid,
                    (VOID **)Fs,
                    gImageHandle,
                    NULL,
                    EFI_OPEN_PROTOCOL_GET_PROTOCOL
                    );
    if (!EFI_ERROR(Status)) {
      gBS->FreePool(HandleBuffer);
      Print(L"Found EFI_SIMPLE_FILE_SYSTEM_PROTOCOL on handle %p\n", HandleBuffer[Index]);
      return EFI_SUCCESS;
    }
  }

  gBS->FreePool(HandleBuffer);
  Print(L"No EFI_SIMPLE_FILE_SYSTEM_PROTOCOL found.\n");
  return EFI_NOT_FOUND;
}





//
//EFI_STATUS
//LoadKernelImage (
//  IN EFI_HANDLE        ImageHandle,
//  IN EFI_SYSTEM_TABLE  *SystemTable
//  )
//{
//  EFI_STATUS                     Status;
//  EFI_SIMPLE_FILE_SYSTEM_PROTOCOL *FsProtocol;
//  EFI_FILE_PROTOCOL              *RootFs;
//  EFI_FILE_PROTOCOL              *KernelFile;
//  VOID                           *KernelBuffer;
//  UINTN                          KernelFileSize;
//  EFI_DEVICE_PATH_PROTOCOL       *KernelDevicePath;
//  EFI_HANDLE                     KernelImageHandle;
//  EFI_MEMORY_DESCRIPTOR          *MemoryMap;
//  UINTN                          MemoryMapSize;
//  UINTN                          MapKey;
//  UINTN                          DescriptorSize;
//  UINT32                         DescriptorVersion;
//  KERNEL_ENTRY_POINT             KernelEntryPoint;
//  EFI_LOADED_IMAGE_PROTOCOL      *KernelLoadedImage;
//  EFI_FILE_INFO                  *FileInfo;
//  UINTN                          FileInfoSize;
//  CHAR16                         *DevicePathText;
//  EFI_DEVICE_PATH_TO_TEXT_PROTOCOL *DevicePathToText;
//  EFI_HANDLE                     FsHandle = NULL;
//
//  // For constructing the file path device node
//  CONST CHAR16                   *KernelFilePathString = L"\\EFI\\rocky\\grubx64.efi"; // Define the path string once
//  UINTN                          FilePathStringLen;
//  UINTN                          FilePathNodeSize;
//  EFI_DEVICE_PATH_PROTOCOL       *FilePathNode; // This will hold the dynamically created file path node
//
//
//  Print(L"KernelLoader: Starting UEFI application.\n");
//
//  Status = LocateSimpleFileSystem(&FsProtocol);
//  if (EFI_ERROR(Status)) {
//    Print(L"ERROR: Could not locate Simple File System Protocol: %r\n", Status);
//    return Status;
//  }
//
//  Status = FsProtocol->OpenVolume (FsProtocol, &RootFs);
//  if (EFI_ERROR(Status)) {
//    Print(L"ERROR: Failed to open root volume: %r\n", Status);
//    return Status;
//  }
//
//  Print(L"Attempting to open kernel file: %s\n", KernelFilePathString);
//  Status = RootFs->Open (
//                     RootFs,
//                     &KernelFile,
//                     (CHAR16*)KernelFilePathString, // Cast to non-const for API
//                     EFI_FILE_MODE_READ,
//                     0
//                     );
//  if (EFI_ERROR(Status)) {
//    Print(L"ERROR: Failed to open kernel file (%s): %r\n", KernelFilePathString, Status);
//    RootFs->Close(RootFs);
//    return Status;
//  }
//  Print(L"Successfully opened kernel file.\n");
//
//  FileInfoSize = 0;
//  FileInfo = NULL;
//  Status = KernelFile->GetInfo(KernelFile, &gEfiFileInfoGuid, &FileInfoSize, NULL);
//  if (Status == EFI_BUFFER_TOO_SMALL) {
//      FileInfo = AllocatePool(FileInfoSize);
//      if (FileInfo == NULL) {
//          Print(L"ERROR: Failed to allocate memory for FileInfo.\n");
//          KernelFile->Close(KernelFile);
//          RootFs->Close(RootFs);
//          return EFI_OUT_OF_RESOURCES;
//      }
//      Status = KernelFile->GetInfo(KernelFile, &gEfiFileInfoGuid, &FileInfoSize, FileInfo);
//  }
//  if (EFI_ERROR(Status)) {
//      Print(L"ERROR: Failed to get kernel file info: %r\n", Status);
//      if (FileInfo) FreePool(FileInfo);
//      KernelFile->Close(KernelFile);
//      RootFs->Close(RootFs);
//      return Status;
//  }
//  KernelFileSize = FileInfo->FileSize;
//  FreePool(FileInfo);
//  Print(L"Kernel file size: %lu bytes\n", (UINT64)KernelFileSize);
//
//  Status = gBS->AllocatePool (EfiLoaderData, KernelFileSize, &KernelBuffer);
//  if (EFI_ERROR(Status)) {
//    Print(L"ERROR: Failed to allocate memory for kernel buffer: %r\n", Status);
//    KernelFile->Close(KernelFile);
//    RootFs->Close(RootFs);
//    return Status;
//  }
//  Print(L"Allocated 0x%lx bytes for kernel at %p\n", (UINT64)KernelFileSize, KernelBuffer);
//
//  Status = KernelFile->Read (KernelFile, &KernelFileSize, KernelBuffer);
//  if (EFI_ERROR(Status)) {
//    Print(L"ERROR: Failed to read kernel file: %r\n", Status);
//    gBS->FreePool(KernelBuffer);
//    KernelFile->Close(KernelFile);
//    RootFs->Close(RootFs);
//    return Status;
//  }
//  Print(L"Successfully read kernel file into memory.\n");
//
//  KernelFile->Close(KernelFile);
//  RootFs->Close(RootFs);
//
//
//  // ***** CORRECTED DEVICE PATH CONSTRUCTION STARTS HERE *****
//
//  // 1. Get the handle of the Simple File System Protocol that corresponds to FsProtocol
//  UINTN NumHandles;
//  EFI_HANDLE *HandleBuffer;
//  UINTN Index;
//
//  Status = gBS->LocateHandleBuffer (
//                  ByProtocol,
//                  &gEfiSimpleFileSystemProtocolGuid,
//                  NULL,
//                  &NumHandles,
//                  &HandleBuffer
//                  );
//  if (EFI_ERROR(Status)) {
//      Print(L"ERROR: Failed to locate handles for Simple File System Protocol: %r\n", Status);
//      gBS->FreePool(KernelBuffer);
//      return Status;
//  }
//
//  FsHandle = NULL; // Reset FsHandle
//  for (Index = 0; Index < NumHandles; Index++) {
//      EFI_SIMPLE_FILE_SYSTEM_PROTOCOL *TempFs = NULL;
//      Status = gBS->OpenProtocol(
//                       HandleBuffer[Index],
//                       &gEfiSimpleFileSystemProtocolGuid,
//                       (VOID**)&TempFs,
//                       gImageHandle,
//                       NULL,
//                       EFI_OPEN_PROTOCOL_GET_PROTOCOL
//                       );
//      if (!EFI_ERROR(Status) && TempFs == FsProtocol) {
//          FsHandle = HandleBuffer[Index];
//          // It's good practice to close a protocol you opened just for comparison
//          gBS->CloseProtocol(HandleBuffer[Index], &gEfiSimpleFileSystemProtocolGuid, gImageHandle, NULL);
//          break;
//      }
//      if (!EFI_ERROR(Status)) {
//          // If we opened it and it's not the one we want, close it
//          gBS->CloseProtocol(HandleBuffer[Index], &gEfiSimpleFileSystemProtocolGuid, gImageHandle, NULL);
//      }
//  }
//  gBS->FreePool(HandleBuffer); // Always free the buffer
//
//  if (FsHandle == NULL) {
//      Print(L"ERROR: Could not find the handle associated with the opened Simple File System Protocol.\n");
//      gBS->FreePool(KernelBuffer);
//      return EFI_NOT_FOUND;
//  }
//
//
//  // 2. Get the device path of the File System Handle
//  EFI_DEVICE_PATH_PROTOCOL *FsDevicePath;
//  Status = gBS->OpenProtocol (
//                  FsHandle,
//                  &gEfiDevicePathProtocolGuid,
//                  (VOID **)&FsDevicePath,
//                  gImageHandle,
//                  NULL,
//                  EFI_OPEN_PROTOCOL_GET_PROTOCOL
//                  );
//  if (EFI_ERROR(Status)) {
//    Print(L"ERROR: Failed to open DevicePathProtocol for FS handle: %r\n", Status);
//    gBS->FreePool(KernelBuffer);
//    return Status;
//  }
//
//  // 3. Dynamically create the file path device node
//  FilePathStringLen = StrLen(KernelFilePathString);
//  // FileNodeSize: Header (4 bytes) + UnicodeString (Length * 2 bytes) + NULL terminator (2 bytes)
//  FilePathNodeSize = sizeof(EFI_DEVICE_PATH_PROTOCOL) + FilePathStringLen * sizeof(CHAR16) + sizeof(CHAR16);
//
//  FilePathNode = (EFI_DEVICE_PATH_PROTOCOL*)AllocatePool(FilePathNodeSize);
//  if (FilePathNode == NULL) {
//      Print(L"ERROR: Failed to allocate memory for FilePathNode.\n");
//      gBS->FreePool(KernelBuffer);
//      return EFI_OUT_OF_RESOURCES;
//  }
//
//  ZeroMem(FilePathNode, FilePathNodeSize);
//
//  FilePathNode->Type    = MEDIA_DEVICE_PATH;
//  FilePathNode->SubType = MEDIA_FILEPATH_DP;
//  FilePathNode->Length[0] = (UINT8)FilePathNodeSize;
//  FilePathNode->Length[1] = (UINT8)(FilePathNodeSize >> 8);
//  //SET_DEVICE_PATH_NODE_LENGTH(FilePathNode, FilePathNodeSize);
//
//  //END_DEVICE_PATH_LENGTH
//  // Copy the file path string into the data area immediately after the header
//  StrCpyS((CHAR16 *)(FilePathNode + 1), 64, KernelFilePathString);
//
//
//  // 4. Append the file path node to the file system's device path
//  KernelDevicePath = AppendDevicePath (FsDevicePath, FilePathNode);
//  //KernelDevicePath = FilePathNode;
//  if (KernelDevicePath == NULL) {
//      Print(L"ERROR: Failed to append device paths.\n");
//      gBS->FreePool(KernelBuffer);
//      gBS->FreePool(FilePathNode);
//      return EFI_OUT_OF_RESOURCES;
//  }
//  gBS->FreePool(FilePathNode); // Free the temporary file path node
//
//
//  // Print the full device path for debugging
//  Status = gBS->LocateProtocol (
//                  &gEfiDevicePathToTextProtocolGuid,
//                  NULL,
//                  (VOID **)&DevicePathToText
//                  );
//  if (!EFI_ERROR(Status)) {
//      DevicePathText = DevicePathToText->ConvertDevicePathToText(KernelDevicePath, FALSE, FALSE);
//      if (DevicePathText != NULL) {
//          Print(L"Kernel Device Path: %s\n", DevicePathText);
//          gBS->FreePool(DevicePathText);
//      }
//  }
//  // ***** CORRECTED DEVICE PATH CONSTRUCTION ENDS HERE *****
//
//
//  // Load the kernel image (rest of the code as before)
//  Print(L"Loading kernel image...\n");
//  Status = gBS->LoadImage (
//                  FALSE,
//                  ImageHandle,
//                  KernelDevicePath,
//                  KernelBuffer,
//                  KernelFileSize,
//                  &KernelImageHandle
//                  );
//  if (EFI_ERROR(Status)) {
//    Print(L"ERROR: Failed to load kernel image: %r\n", Status);
//    gBS->FreePool(KernelBuffer);
//    gBS->FreePool(KernelDevicePath);
//    return Status;
//  }
//  Print(L"Kernel image loaded successfully. KernelImageHandle: %p\n", KernelImageHandle);
//  gBS->FreePool(KernelDevicePath);
//
//  Status = gBS->OpenProtocol (
//                  KernelImageHandle,
//                  &gEfiLoadedImageProtocolGuid,
//                  (VOID **)&KernelLoadedImage,
//                  gImageHandle,
//                  NULL,
//                  EFI_OPEN_PROTOCOL_GET_PROTOCOL
//                  );
//  if (EFI_ERROR(Status)) {
//    Print(L"ERROR: Failed to open KernelLoadedImageProtocol: %r\n", Status);
//    gBS->FreePool(KernelBuffer);
//    gBS->UnloadImage(KernelImageHandle);
//    return Status;
//  }
//  KernelEntryPoint = (KERNEL_ENTRY_POINT)KernelLoadedImage->EntryPoint;
//  Print(L"Kernel Entry Point obtained: %p\n", KernelEntryPoint);
//
//
//  MemoryMapSize = 0;
//  MemoryMap = NULL;
//  MapKey = 0;
//  DescriptorSize = 0;
//  DescriptorVersion = 0;
//
//  Status = gBS->GetMemoryMap (
//                  &MemoryMapSize,
//                  MemoryMap,
//                  &MapKey,
//                  &DescriptorSize,
//                  &DescriptorVersion
//                  );
//  while (Status == EFI_BUFFER_TOO_SMALL) {
//    MemoryMapSize += EFI_PAGE_SIZE * 2;
//    if (MemoryMap != NULL) {
//      gBS->FreePool(MemoryMap);
//    }
//    Status = gBS->AllocatePool (EfiLoaderData, MemoryMapSize, (VOID **)&MemoryMap);
//    if (EFI_ERROR(Status)) {
//      Print(L"ERROR: Failed to allocate memory for memory map: %r\n", Status);
//      gBS->FreePool(KernelBuffer);
//      gBS->UnloadImage(KernelImageHandle);
//      if (MemoryMap) gBS->FreePool(MemoryMap);
//      return Status;
//    }
//    Status = gBS->GetMemoryMap (
//                    &MemoryMapSize,
//                    MemoryMap,
//                    &MapKey,
//                    &DescriptorSize,
//                    &DescriptorVersion
//                    );
//  }
//
//  if (EFI_ERROR(Status)) {
//    Print(L"ERROR: Failed to get memory map: %r\n", Status);
//    gBS->FreePool(KernelBuffer);
//    gBS->UnloadImage(KernelImageHandle);
//    if (MemoryMap) gBS->FreePool(MemoryMap);
//    return Status;
//  }
//  Print(L"Memory map obtained. MapKey: %lu, Size: %lu, DescriptorSize: %lu\n",
//        (UINT64)MapKey, (UINT64)MemoryMapSize, (UINT64)DescriptorSize);
//
//
//  Print(L"Exiting Boot Services...\n");
//  Status = gBS->ExitBootServices (ImageHandle, MapKey);
//  if (EFI_ERROR(Status)) {
//    Print(L"FATAL ERROR: Failed to exit boot services: %r\n", Status);
//    while (TRUE);
//  }
//  Print(L"Successfully exited Boot Services.\n");
//
//
//  Print(L"Jumping to kernel entry point at %p...\n", KernelEntryPoint);
//
//  KernelEntryPoint(
//    gST,
//    MemoryMap,
//    MemoryMapSize,
//    DescriptorSize,
//    NULL
//    );
//
//  Print(L"FATAL ERROR: Kernel returned or failed to boot!\n");
//  while (TRUE);
//
//  return EFI_SUCCESS;
//}
//
//
//


//#include <Uefi.h>
//#include <Library/UefiBootServicesTableLib.h>
//#include <Library/UefiRuntimeServicesTableLib.h>
//#include <Library/UefiLib.h>
//#include <Library/MemoryAllocationLib.h>
//#include <Library/DevicePathLib.h>
//#include <Library/DebugLib.h>
//
//// Protocols
//#include <Protocol/LoadedImage.h>
//#include <Protocol/SimpleFileSystem.h>
//#include <Protocol/BlockIo.h>
//#include <Protocol/DevicePathToText.h>
//#include <Protocol/DevicePathFromText.h>
//
//#include <Guid/FileInfo.h>
//
//// Define the kernel entry point signature.
//typedef VOID (*KERNEL_ENTRY_POINT)(
//  IN EFI_SYSTEM_TABLE  *SystemTable,
//  IN EFI_MEMORY_DESCRIPTOR *MemoryMap,
//  IN UINTN             MemoryMapSize,
//  IN UINTN             DescriptorSize,
//  IN VOID              *Reserved
//  );
//
//// Helper function to locate the first Simple File System Protocol (as before)
//EFI_STATUS
//LocateKernelFileSystem (
//  OUT EFI_SIMPLE_FILE_SYSTEM_PROTOCOL **Fs
//  )
//{
//  EFI_STATUS  Status;
//  UINTN       NumHandles;
//  EFI_HANDLE  *HandleBuffer;
//  UINTN       Index;
//
//  Status = gBS->LocateHandleBuffer (
//                  ByProtocol,
//                  &gEfiSimpleFileSystemProtocolGuid,
//                  NULL,
//                  &NumHandles,
//                  &HandleBuffer
//                  );
//  if (EFI_ERROR(Status)) {
//    Print(L"LocateHandleBuffer(gEfiSimpleFileSystemProtocolGuid) failed: %r\n", Status);
//    return Status;
//  }
//
//  for (Index = 0; Index < NumHandles; Index++) {
//    Status = gBS->OpenProtocol (
//                    HandleBuffer[Index],
//                    &gEfiSimpleFileSystemProtocolGuid,
//                    (VOID **)Fs,
//                    gImageHandle,
//                    NULL,
//                    EFI_OPEN_PROTOCOL_GET_PROTOCOL
//                    );
//    if (!EFI_ERROR(Status)) {
//      gBS->FreePool(HandleBuffer);
//      Print(L"Found EFI_SIMPLE_FILE_SYSTEM_PROTOCOL on handle %p\n", HandleBuffer[Index]);
//      return EFI_SUCCESS;
//    }
//  }
//
//  gBS->FreePool(HandleBuffer);
//  Print(L"No EFI_SIMPLE_FILE_SYSTEM_PROTOCOL found.\n");
//  return EFI_NOT_FOUND;
//}
//
//
//EFI_STATUS
//LoadKernelImage (
//  IN EFI_HANDLE        ImageHandle,
//  IN EFI_SYSTEM_TABLE  *SystemTable
//  )
//{
//  EFI_STATUS                     Status;
//  EFI_SIMPLE_FILE_SYSTEM_PROTOCOL *FsProtocol;
//  EFI_FILE_PROTOCOL              *RootFs;
//  EFI_FILE_PROTOCOL              *KernelFile;
//  VOID                           *KernelBuffer;
//  UINTN                          KernelFileSize;
//  EFI_DEVICE_PATH_PROTOCOL       *KernelDevicePath;
//  EFI_HANDLE                     KernelImageHandle;
//  EFI_MEMORY_DESCRIPTOR          *MemoryMap;
//  UINTN                          MemoryMapSize;
//  UINTN                          MapKey;
//  UINTN                          DescriptorSize;
//  UINT32                         DescriptorVersion;
//  KERNEL_ENTRY_POINT             KernelEntryPoint;
//  EFI_LOADED_IMAGE_PROTOCOL      *KernelLoadedImage; // Declare here
//  EFI_FILE_INFO                  *FileInfo;
//  UINTN                          FileInfoSize;
//  CHAR16                         *DevicePathText;
//  EFI_DEVICE_PATH_TO_TEXT_PROTOCOL *DevicePathToText;
//  EFI_HANDLE                     FsHandle = NULL; // Initialize FsHandle
//
//  Print(L"KernelLoader: Starting UEFI application.\n");
//
//  Status = LocateKernelFileSystem(&FsProtocol);
//  if (EFI_ERROR(Status)) {
//    Print(L"ERROR: Could not locate Simple File System Protocol: %r\n", Status);
//    return Status;
//  }
//
//  Status = FsProtocol->OpenVolume (FsProtocol, &RootFs);
//  if (EFI_ERROR(Status)) {
//    Print(L"ERROR: Failed to open root volume: %r\n", Status);
//    return Status;
//  }
//
//  Print(L"Attempting to open kernel file: \\EFI\\BOOT\\KERNEL.EFI\n");
//  Status = RootFs->Open (
//                     RootFs,
//                     &KernelFile,
//                     L"\\EFI\\BOOT\\KERNEL.EFI", // Adjust this path!
//                     EFI_FILE_MODE_READ,
//                     0
//                     );
//  if (EFI_ERROR(Status)) {
//    Print(L"ERROR: Failed to open kernel file (\\EFI\\BOOT\\KERNEL.EFI): %r\n", Status);
//    RootFs->Close(RootFs);
//    return Status;
//  }
//  Print(L"Successfully opened kernel file.\n");
//
//  FileInfoSize = 0;
//  FileInfo = NULL;
//  Status = KernelFile->GetInfo(KernelFile, &gEfiFileInfoGuid, &FileInfoSize, NULL);
//  if (Status == EFI_BUFFER_TOO_SMALL) {
//      FileInfo = AllocatePool(FileInfoSize);
//      if (FileInfo == NULL) {
//          Print(L"ERROR: Failed to allocate memory for FileInfo.\n");
//          KernelFile->Close(KernelFile);
//          RootFs->Close(RootFs);
//          return EFI_OUT_OF_RESOURCES;
//      }
//      Status = KernelFile->GetInfo(KernelFile, &gEfiFileInfoGuid, &FileInfoSize, FileInfo);
//  }
//  if (EFI_ERROR(Status)) {
//      Print(L"ERROR: Failed to get kernel file info: %r\n", Status);
//      if (FileInfo) FreePool(FileInfo);
//      KernelFile->Close(KernelFile);
//      RootFs->Close(RootFs);
//      return Status;
//  }
//  KernelFileSize = FileInfo->FileSize;
//  FreePool(FileInfo);
//  Print(L"Kernel file size: %lu bytes\n", (UINT64)KernelFileSize);
//
//  Status = gBS->AllocatePool (EfiLoaderData, KernelFileSize, &KernelBuffer);
//  if (EFI_ERROR(Status)) {
//    Print(L"ERROR: Failed to allocate memory for kernel buffer: %r\n", Status);
//    KernelFile->Close(KernelFile);
//    RootFs->Close(RootFs);
//    return Status;
//  }
//  Print(L"Allocated 0x%lx bytes for kernel at %p\n", (UINT64)KernelFileSize, KernelBuffer);
//
//  Status = KernelFile->Read (KernelFile, &KernelFileSize, KernelBuffer);
//  if (EFI_ERROR(Status)) {
//    Print(L"ERROR: Failed to read kernel file: %r\n", Status);
//    gBS->FreePool(KernelBuffer);
//    KernelFile->Close(KernelFile);
//    RootFs->Close(RootFs);
//    return Status;
//  }
//  Print(L"Successfully read kernel file into memory.\n");
//
//  KernelFile->Close(KernelFile);
//  RootFs->Close(RootFs);
//
//
//  // Construct the device path for the kernel image (as before)
//  UINTN NumHandles;
//  EFI_HANDLE *HandleBuffer;
//  UINTN Index;
//
//  Status = gBS->LocateHandleBuffer (
//                  ByProtocol,
//                  &gEfiSimpleFileSystemProtocolGuid,
//                  NULL,
//                  &NumHandles,
//                  &HandleBuffer
//                  );
//  if (!EFI_ERROR(Status)) {
//      for (Index = 0; Index < NumHandles; Index++) {
//          EFI_SIMPLE_FILE_SYSTEM_PROTOCOL *TempFs = NULL;
//          Status = gBS->OpenProtocol(
//                           HandleBuffer[Index],
//                           &gEfiSimpleFileSystemProtocolGuid,
//                           (VOID**)&TempFs,
//                           gImageHandle,
//                           NULL,
//                           EFI_OPEN_PROTOCOL_GET_PROTOCOL
//                           );
//          if (!EFI_ERROR(Status) && TempFs == FsProtocol) {
//              FsHandle = HandleBuffer[Index];
//              break;
//          }
//      }
//      gBS->FreePool(HandleBuffer);
//  }
//
//  if (EFI_ERROR(Status) || FsHandle == NULL) {
//      Print(L"ERROR: Could not get handle for Simple File System Protocol: %r\n", Status);
//      gBS->FreePool(KernelBuffer);
//      return Status;
//  }
//
//  EFI_DEVICE_PATH_PROTOCOL *FsDevicePath;
//  Status = gBS->OpenProtocol (
//                  FsHandle,
//                  &gEfiDevicePathProtocolGuid,
//                  (VOID **)&FsDevicePath,
//                  gImageHandle,
//                  NULL,
//                  EFI_OPEN_PROTOCOL_GET_PROTOCOL
//                  );
//  if (EFI_ERROR(Status)) {
//    Print(L"ERROR: Failed to open DevicePathProtocol for FS handle: %r\n", Status);
//    gBS->FreePool(KernelBuffer);
//    return Status;
//  }
//
//  EFI_DEVICE_PATH_PROTOCOL *FileDevicePath = FileDevicePathFromText(L"\\EFI\\rocky\\grubx64.EFI");
//  if (FileDevicePath == NULL) {
//      Print(L"ERROR: Failed to create file device path from text.\n");
//      gBS->FreePool(KernelBuffer);
//      return EFI_OUT_OF_RESOURCES;
//  }
//  KernelDevicePath = AppendDevicePath(FsDevicePath, FileDevicePath);
//  if (KernelDevicePath == NULL) {
//      Print(L"ERROR: Failed to append device paths.\n");
//      gBS->FreePool(KernelBuffer);
//      gBS->FreePool(FileDevicePath);
//      return EFI_OUT_OF_RESOURCES;
//  }
//  gBS->FreePool(FileDevicePath);
//
//  Status = gBS->LocateProtocol (
//                  &gEfiDevicePathToTextProtocolGuid,
//                  NULL,
//                  (VOID **)&DevicePathToText
//                  );
//  if (!EFI_ERROR(Status)) {
//      DevicePathText = DevicePathToText->ConvertDevicePathToText(KernelDevicePath, FALSE, FALSE);
//      if (DevicePathText != NULL) {
//          Print(L"Kernel Device Path: %s\n", DevicePathText);
//          gBS->FreePool(DevicePathText);
//      }
//  }
//
//
//  // Load the kernel image
//  Print(L"Loading kernel image...\n");
//  Status = gBS->LoadImage (
//                  FALSE,            // Not a BootOption
//                  ImageHandle,      // Parent image handle (our own handle)
//                  KernelDevicePath, // Device path of the image to load
//                  KernelBuffer,     // Buffer containing the image data
//                  KernelFileSize,   // Size of the image data
//                  &KernelImageHandle// Handle for the loaded image
//                  );
//  if (EFI_ERROR(Status)) {
//    Print(L"ERROR: Failed to load kernel image: %r\n", Status);
//    gBS->FreePool(KernelBuffer);
//    gBS->FreePool(KernelDevicePath);
//    return Status;
//  }
//  Print(L"Kernel image loaded successfully. KernelImageHandle: %p\n", KernelImageHandle);
//  gBS->FreePool(KernelDevicePath); // Free the constructed device path
//
//  // ***** IMPORTANT CORRECTION STARTS HERE *****
//  // Get the kernel's Loaded Image Protocol and its entry point *BEFORE* ExitBootServices.
//  Status = gBS->OpenProtocol (
//                  KernelImageHandle,
//                  &gEfiLoadedImageProtocolGuid,
//                  (VOID **)&KernelLoadedImage,
//                  gImageHandle, // Our ImageHandle as agent
//                  NULL,
//                  EFI_OPEN_PROTOCOL_GET_PROTOCOL
//                  );
//  if (EFI_ERROR(Status)) {
//    Print(L"ERROR: Failed to open KernelLoadedImageProtocol: %r\n", Status);
//    gBS->FreePool(KernelBuffer);
//    gBS->UnloadImage(KernelImageHandle); // Unload the image if we can't get its info
//    return Status;
//  }
//  // Store the entry point address
//  //KernelEntryPoint = (KERNEL_ENTRY_POINT)KernelLoadedImage->EntryPoint;
//  KernelEntryPoint = (KERNEL_ENTRY_POINT)KernelLoadedImage->ImageBase;
//  Print(L"Kernel Entry Point obtained: %p\n", KernelEntryPoint);
//  // We can close the protocol here if we want, or keep it open.
//  // The important thing is that we have the EntryPoint address now.
//  // gBS->CloseProtocol(KernelImageHandle, &gEfiLoadedImageProtocolGuid, gImageHandle, NULL);
//  // ***** IMPORTANT CORRECTION ENDS HERE *****
//
//
//  // Prepare for kernel execution (Exit Boot Services)
//  MemoryMapSize = 0;
//  MemoryMap = NULL;
//  MapKey = 0;
//  DescriptorSize = 0;
//  DescriptorVersion = 0;
//
//  Status = gBS->GetMemoryMap (
//                  &MemoryMapSize,
//                  MemoryMap,
//                  &MapKey,
//                  &DescriptorSize,
//                  &DescriptorVersion
//                  );
//  while (Status == EFI_BUFFER_TOO_SMALL) {
//    MemoryMapSize += EFI_PAGE_SIZE * 2;
//    if (MemoryMap != NULL) {
//      gBS->FreePool(MemoryMap);
//    }
//    Status = gBS->AllocatePool (EfiLoaderData, MemoryMapSize, (VOID **)&MemoryMap);
//    if (EFI_ERROR(Status)) {
//      Print(L"ERROR: Failed to allocate memory for memory map: %r\n", Status);
//      gBS->FreePool(KernelBuffer);
//      gBS->UnloadImage(KernelImageHandle);
//      if (MemoryMap) gBS->FreePool(MemoryMap);
//      return Status;
//    }
//    Status = gBS->GetMemoryMap (
//                    &MemoryMapSize,
//                    MemoryMap,
//                    &MapKey,
//                    &DescriptorSize,
//                    &DescriptorVersion
//                    );
//  }
//
//  if (EFI_ERROR(Status)) {
//    Print(L"ERROR: Failed to get memory map: %r\n", Status);
//    gBS->FreePool(KernelBuffer);
//    gBS->UnloadImage(KernelImageHandle);
//    if (MemoryMap) gBS->FreePool(MemoryMap);
//    return Status;
//  }
//  Print(L"Memory map obtained. MapKey: %lu, Size: %lu, DescriptorSize: %lu\n",
//        (UINT64)MapKey, (UINT64)MemoryMapSize, (UINT64)DescriptorSize);
//
//
//  // Exit Boot Services
//  Print(L"Exiting Boot Services...\n");
//  Status = gBS->ExitBootServices (ImageHandle, MapKey);
//  if (EFI_ERROR(Status)) {
//    Print(L"FATAL ERROR: Failed to exit boot services: %r\n", Status);
//    // This is a critical error. The system will likely hang.
//    while (TRUE);
//  }
//  Print(L"Successfully exited Boot Services.\n");
//
//
//  // Transfer control to the kernel
//  Print(L"Jumping to kernel entry point at %p...\n", KernelEntryPoint);
//
//  // Jump to the kernel.
//  KernelEntryPoint(
//    gST,
//    MemoryMap,
//    MemoryMapSize,
//    DescriptorSize,
//    NULL
//    );
//
//  // If the kernel returns, it means it failed to boot.
//  Print(L"FATAL ERROR: Kernel returned or failed to boot!\n");
//  while (TRUE);
//
//  return EFI_SUCCESS;
//}
