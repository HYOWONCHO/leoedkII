#include <Uefi.h>       // Standard UEFI headers
#include <Library/UefiBootServicesTableLib.h> // For gBS (Boot Services)
#include <Library/UefiLib.h>      // For Print, AsciiPrint
#include <Library/DebugLib.h>     // For DEBUG macros
#include <Library/MemoryAllocationLib.h> // For AllocatePool, FreePool
#include <Protocol/SimpleFileSystem.h> // For EFI_SIMPLE_FILE_SYSTEM_PROTOCOL
//#include <Protocol/File.h>        // For EFI_FILE_PROTOCOL
#include <Library/PrintLib.h>
#include <Protocol/DevicePath.h>  // For EFI_DEVICE_PATH_PROTOCOL (needed by LoadImage)

#include <Protocol/LoadedImage.h>
#include <Library/DevicePathLib.h>
#include <Protocol/DevicePathFromText.h>
#include <Guid/FileInfo.h>

#include "SBC_FileCtrl.h"

// Define the path to grubx64.efi relative to the root of the file system
// Adjust this path if your grubx64.efi is located elsewhere (e.g., "\EFI\ubuntu\grubx64.efi")
#define GRUB_EFI_PATH L"\\EFI\\rocky\\grubx64.efi"

/**
  The user Entry Point for Application.

  This function searches for grubx64.efi on all available file systems,
  loads it, and then starts it.

  @param[in] ImageHandle    The firmware allocated handle for the EFI image.
  @param[in] SystemTable    A pointer to the EFI System Table.

  @retval EFI_SUCCESS       grubx64.efi was successfully loaded and started.
  @retval other             An error occurred.
**/
EFI_STATUS
LoadKernelImage (
  IN EFI_HANDLE        ImageHandle,
  IN EFI_SYSTEM_TABLE  *SystemTable
  )
{
  EFI_STATUS                    Status;
  UINTN                         NumHandles;
  EFI_HANDLE                    *ControllerHandleBuffer;
  UINTN                         Index;
  EFI_SIMPLE_FILE_SYSTEM_PROTOCOL *FsProtocol;
  EFI_FILE_PROTOCOL             *Root;
  EFI_FILE_PROTOCOL             *GrubFile;
  EFI_HANDLE                    GrubImageHandle;
  EFI_DEVICE_PATH_PROTOCOL      *GrubDevicePath;
  CHAR16                        GrubFullPath[256]; // Buffer for the full path

  Print(L"GrubLauncherApp: Starting to search for %s...\n", GRUB_EFI_PATH);
  dprint( "GrubLauncherApp: EntryPoint.\n");

  ControllerHandleBuffer = NULL;
  GrubImageHandle        = NULL;
  GrubFile               = NULL;
  Root                   = NULL;
  GrubDevicePath         = NULL;

  //
  // 1. Locate all handles that support the Simple File System Protocol.
  //    These handles represent available file system volumes (e.g., USB drives, HDDs).
  //
  Status = gBS->LocateHandleBuffer (
                  ByProtocol,
                  &gEfiSimpleFileSystemProtocolGuid,
                  NULL,
                  &NumHandles,
                  &ControllerHandleBuffer
                  );

  if (EFI_ERROR (Status)) {
    Print(L"GrubLauncherApp: No Simple File System Protocol instances found (%r).\n", Status);
    eprint("GrubLauncherApp: LocateHandleBuffer failed: %r\n", Status);
    return Status;
  }

  //
  // 2. Iterate through each found file system handle.
  //
  for (Index = 0; Index < NumHandles; Index++) {
    Print(L"GrubLauncherApp: Checking FS%d...\n", Index);
    dprint( "GrubLauncherApp: Checking handle %p.\n", ControllerHandleBuffer[Index]);

    //
    // Open the Simple File System Protocol on the current handle.
    //
    Status = gBS->OpenProtocol (
                    ControllerHandleBuffer[Index],
                    &gEfiSimpleFileSystemProtocolGuid,
                    (VOID **) &FsProtocol,
                    gImageHandle,
                    NULL,
                    EFI_OPEN_PROTOCOL_GET_PROTOCOL
                    );

    if (EFI_ERROR (Status)) {
      eprint("GrubLauncherApp: Failed to open Simple File System Protocol on handle %p: %r\n", ControllerHandleBuffer[Index], Status);
      continue; // Skip to the next handle
    }

    //
    // Open the root directory of the file system.
    //
    Status = FsProtocol->OpenVolume (
                           FsProtocol,
                           &Root
                           );
    if (EFI_ERROR (Status)) {
      eprint("GrubLauncherApp: Failed to open volume on handle %p: %r\n", ControllerHandleBuffer[Index], Status);
      // Root might be NULL if OpenVolume failed, so ensure to not close it.
      Root = NULL;
      continue;
    }

    //
    // Try to open grubx64.efi file.
    //
    Status = Root->Open (
                     Root,
                     &GrubFile,
                     GRUB_EFI_PATH,
                     EFI_FILE_MODE_READ,
                     0
                     );

    if (EFI_ERROR (Status)) {
      dprint( "GrubLauncherApp: %s not found on FS%d: %r\n", GRUB_EFI_PATH, Index, Status);
      // Close the root directory before continuing to the next file system.
      if (Root != NULL) {
        Root->Close(Root);
        Root = NULL;
      }
      continue; // File not found, try next file system
    }

    //
    // 3. Grubx64.efi found! Now, construct its device path.
    //    We need the device path of the file to load the image.
    //
    Status = gBS->HandleProtocol (
                    ControllerHandleBuffer[Index],
                    &gEfiDevicePathProtocolGuid,
                    (VOID **) &GrubDevicePath
                    );
    if (EFI_ERROR (Status)) {
      eprint("GrubLauncherApp: Failed to get device path protocol for handle %p: %r\n", ControllerHandleBuffer[Index], Status);
      // Close resources before failing
      GrubFile->Close(GrubFile);
      Root->Close(Root);
      FreePool(ControllerHandleBuffer);
      return Status;
    }

    // Concatenate the file path to the device path of the volume.
    // Note: This creates a new device path node for the file itself.
    // This part is a bit tricky, typically you'd append a FilePathDevicePath node.
    // For simplicity, we'll assume LoadImage can work with the device path of the volume
    // and a file path string, as EDK II's LoadImage has overloaded behavior.
    // The Print() statement below just shows the expected full path string.
    UnicodeSPrint(GrubFullPath, sizeof(GrubFullPath), L"%s%s",
      L"\\", // Assuming root is the base, GRUB_EFI_PATH starts with '\'
      GRUB_EFI_PATH + 1 // Skip the leading '\'
    );
    // Correct way for LoadImage with file path: build a full device path
    // or use a simpler LoadImage variant if available.
    // EDK II's LoadImage can often take a FilePathDevicePath created from a device handle
    // and a relative path.
    // The easiest way is often to use DevicePathFromText and append the file path,
    // but that requires DevicePathFromTextLib. Let's use the ImageHandle for the device path
    // and the file path string if LoadImage supports it directly, which it does.


    Print(L"a GrubLauncherApp: Found %s on FS%d. Attempting to load...\n", GrubFullPath, Index);
    dprint( "GrubLauncherApp: Calling LoadImage with %s.\n", GRUB_EFI_PATH);

    //
    // Load the GRUB EFI image into memory.
    // The second parameter is the DevicePath of the parent handle + the file path.
    // EDK II's gBS->LoadImage can take the parent handle's device path and
    // the file path string directly.
    //
    Status = gBS->LoadImage (
                    FALSE,                  // Boot Policy: FALSE for no-boot-policy (application)
                    gImageHandle,            // ImageHandle of the caller (this application)
                    GrubDevicePath,         // Device path of the device where grubx64.efi resides
                    NULL,                   // Buffer: If NULL, LoadImage allocates memory
                    0,                      // BufferSize: If 0, LoadImage reads entire file
                    &GrubImageHandle        // Output: Handle of the loaded image
                    );

    if (EFI_ERROR (Status)) {
      Print(L"GrubLauncherApp: Failed to load %s: %r\n", GRUB_EFI_PATH, Status);
      eprint("GrubLauncherApp: LoadImage failed for %s: %r\n", GRUB_EFI_PATH, Status);
      // Close resources and try next FS if LoadImage fails
      GrubFile->Close(GrubFile);
      Root->Close(Root);
      continue;
    }

    Print(L"GrubLauncherApp: %s loaded successfully. Starting...\n", GRUB_EFI_PATH);
    dprint( "GrubLauncherApp: Starting loaded GRUB image.\n");

    //
    // 4. Start the loaded GRUB image.
    // This transfers control to grubx64.efi's entry point.
    //
    Status = gBS->StartImage (
                    GrubImageHandle,
                    NULL,
                    NULL
                    );

    if (EFI_ERROR (Status)) {
      Print(L"GrubLauncherApp: Failed to start %s: %r\n", GRUB_EFI_PATH, Status);
      eprint("GrubLauncherApp: StartImage failed for %s: %r\n", GRUB_EFI_PATH, Status);
      // If StartImage fails, you might want to unload the image.
      gBS->UnloadImage(GrubImageHandle);
      // Close resources and continue searching or exit.
      GrubFile->Close(GrubFile);
      Root->Close(Root);
      FreePool(ControllerHandleBuffer);
      return Status; // Exit if failed to start
    } else {
      // If StartImage returns EFI_SUCCESS, it means GRUB successfully
      // executed and then returned control to this application.
      // This happens if GRUB exits without booting an OS, or if it
      // returns control under specific circumstances.
      // If GRUB successfully boots an OS, StartImage typically won't return.
      Print(L"GrubLauncherApp: %s started and returned control.\n", GRUB_EFI_PATH);
      // Unload the GRUB image as it has returned control.
      gBS->UnloadImage(GrubImageHandle);
      // Success, so clean up and exit.
      GrubFile->Close(GrubFile);
      Root->Close(Root);
      FreePool(ControllerHandleBuffer);
      return EFI_SUCCESS;
    }
  }

  // If we reach here, grubx64.efi was not found on any file system.
  Print(L"GrubLauncherApp: ERROR - %s not found on any accessible file system.\n", GRUB_EFI_PATH);
  eprint("GrubLauncherApp: %s not found.\n", GRUB_EFI_PATH);

  // Clean up allocated buffer
  if (ControllerHandleBuffer != NULL) {
    FreePool(ControllerHandleBuffer);
  }

  return EFI_NOT_FOUND;
}


// Forward declaration for the helper function
EFI_STATUS
LocateDevicePathForFile (
  IN  EFI_HANDLE                 ParentImageHandle,
  IN  CHAR16                     *FileName,
  OUT EFI_DEVICE_PATH_PROTOCOL   **DevicePath
  );

VOID LoadFile(EFI_HANDLE        ImageHandle,VOID **rdout, UINTN *rdlen)
{

  EFI_STATUS retval;
  EFI_HANDLE h_img =NULL;
  CHAR16 *ssblpath = L"\\EFI\\boot\\SSBL.efi";
  
  UINTN len;
  LV_t lvout;

  SBC_FileSysFindHndl(&h_img);
  if (SBC_GetFileSize(ssblpath, &len) != SBCOK) {
    Print(L"File size unknowns \n");
    return;
  }

  Print(L"File Size : %d \n", len);
  *rdout = AllocateZeroPool(len);

  lvout.value = rdout;
  lvout.length = len;
  retval = SBC_ReadFile(h_img, ssblpath, &lvout);
  Print(L"Read Status : %r \n", retval);

  *rdlen = lvout.length;


  return;
}


SBCStatus SBC_GRUB_LoadAndStart(EFI_HANDLE ImageHandle)
{
  EFI_HANDLE *Handles;
  UINTN HandleCount;
  //EFI_SIMPLE_FILE_SYSTEM_PROTOCOL *Fs;
  EFI_DEVICE_PATH_PROTOCOL *DevicePath;
  //EFI_HANDLE imghandle;
  CHAR16 *PathStr;

  gBS->LocateHandleBuffer(ByProtocol, &gEfiSimpleFileSystemProtocolGuid, NULL, &HandleCount, &Handles);

  for (UINTN i = 0; i < HandleCount; i++) {
    DevicePath = FileDevicePath(Handles[i], L"\\EFI\\rocky\\grubx64.efi");
    PathStr = ConvertDevicePathToText(DevicePath, TRUE, TRUE);
    if (PathStr != NULL) {
      Print(L"Device Path: %s\n", PathStr);
      FreePool(PathStr);
    } else {
      Print(L"Failed to convert device path to string.\n");
      //return SBCFAIL;
    }
    EFI_STATUS Status = gBS->LoadImage(FALSE, gImageHandle, DevicePath, NULL, 0, &ImageHandle);
    if (!EFI_ERROR(Status)) {
      gBS->StartImage(ImageHandle, NULL, NULL);
      break;
    }
  }

  return SBCOK;
}

SBCStatus SBC_SSBL_LoadAndStart(EFI_HANDLE ImageHandle)
{
  EFI_HANDLE *Handles;
  UINTN HandleCount;
  //EFI_SIMPLE_FILE_SYSTEM_PROTOCOL *Fs;
  EFI_DEVICE_PATH_PROTOCOL *DevicePath;
  //EFI_HANDLE imghandle;
  CHAR16 *PathStr;
  //UINTN hndlcnt;

  gBS->LocateHandleBuffer(ByProtocol, &gEfiSimpleFileSystemProtocolGuid, NULL, &HandleCount, &Handles);

  for (UINTN i = 0; i < HandleCount; i++) {
    DevicePath = FileDevicePath(Handles[i], L"\\EFI\\rocky\\SSBL.efi");
    PathStr = ConvertDevicePathToText(DevicePath, TRUE, TRUE);
    if (PathStr != NULL) {
      Print(L"Device Path: %s\n", PathStr);
      FreePool(PathStr);
    } else {
      Print(L"Failed to convert device path to string.\n");
      //return SBCFAIL;
    }
    EFI_STATUS Status = gBS->LoadImage(FALSE, gImageHandle, DevicePath, NULL, 0, &ImageHandle);
    if (!EFI_ERROR(Status)) {
      gBS->StartImage(ImageHandle, NULL, NULL);
      return SBCOK;
    }
  }

  return SBCFAIL;
}

EFI_STATUS
SSBL_Load (
  IN EFI_HANDLE        ImageHandle,
  IN EFI_SYSTEM_TABLE  *SystemTable
  )
{
  EFI_STATUS                 Status;
  EFI_DEVICE_PATH_PROTOCOL   *TargetAppDevicePath = NULL;
  EFI_HANDLE                 TargetAppImageHandle = NULL;
  EFI_LOADED_IMAGE_PROTOCOL  *TargetAppLoadedImage = NULL;
  CHAR16                     *CommandLineArgs = L"arg1 arg2 --option=value"; // Example command-line arguments
  UINTN                      CommandLineSize = 0;
  //EFI_STATUS                 ExitStatus;
  UINTN                      ExitDataSize;
  CHAR16                     *ExitData;

//VOID                        *rdbuf = NULL;
//UINTN                       rdlen;
//LoadFile(ImageHandle, &rdbuf, &rdlen);
  // 1. Get the device path to the target EFI executable
  // Assuming TargetApp.efi is in the same directory as MyLauncher.efi
  Status = LocateDevicePathForFile(ImageHandle, L"\\EFI\\boot\\SSBL.efi", &TargetAppDevicePath);
  Print(L"Return code : %d \n", Status);
  if (EFI_ERROR(Status)) {
    Print(L"Failed to locate device path for TargetApp.efi: %r\n", Status);
    return Status;
  }


  // 2. Load the target image
  Print(L"Loading TargetApp.efi...\n");
  Status = gBS->LoadImage(
                  FALSE,                 // Not a driver
                  ImageHandle,           // Parent image handle (this application's handle)
                  TargetAppDevicePath,   // Device path to the target .efi file
                  NULL,                  // Buffer (firmware allocates if NULL)
                  0,                     // Buffer size (ignored if Buffer is NULL)
                  &TargetAppImageHandle  // Output: Handle of the loaded image
                  );


//Print(L"File Size : %d Buff addr : %p \n" , rdlen, rdbuf);
//Status = gBS->LoadImage(
//              FALSE,                 // Not a driver
//              ImageHandle,           // Parent image handle (this application's handle)
//              NULL,   // Device path to the target .efi file
//              rdbuf,                  // Buffer (firmware allocates if NULL)
//              rdlen,                     // Buffer size (ignored if Buffer is NULL)
//              &TargetAppImageHandle  // Output: Handle of the loaded image
//              );
  if (EFI_ERROR(Status)) {
    Print(L"Failed to load TargetApp.efi: %r\n", Status);
    FreePool(TargetAppDevicePath); // Free the device path
    return Status;
  }
  Print(L"TargetApp.efi loaded successfully.\n");

  // Optional: Set command-line arguments for the launched application
  CommandLineSize = StrSize(CommandLineArgs); // Size in bytes, including null terminator
  Status = gBS->HandleProtocol(
                  TargetAppImageHandle,
                  &gEfiLoadedImageProtocolGuid,
                  (VOID **)&TargetAppLoadedImage
                  );
  if (!EFI_ERROR(Status)) {
    // Allocate memory for load options
    TargetAppLoadedImage->LoadOptions = AllocateCopyPool(CommandLineSize, CommandLineArgs);
    if (TargetAppLoadedImage->LoadOptions != NULL) {
      TargetAppLoadedImage->LoadOptionsSize = (UINT32)CommandLineSize;
      Print(L"Set load options for TargetApp.efi: \"%s\"\n", CommandLineArgs);
    } else {
      Print(L"Warning: Failed to allocate memory for load options.\n");
    }
  } else {
    Print(L"Warning: Could not get LoadedImageProtocol for TargetApp.efi: %r\n", Status);
  }

  // 3. Start the loaded image
  Print(L"Starting TargetApp.efi...\n");
  Status = gBS->StartImage(
                  TargetAppImageHandle, // Handle of the image to start
                  &ExitDataSize,        // Output: Size of exit data
                  &ExitData             // Output: Pointer to exit data (if any)
                  );

  // 4. Handle the return status and cleanup
  if (EFI_ERROR(Status)) {
    Print(L"Failed to start TargetApp.efi: %r\n", Status);
  } else {
    Print(L"TargetApp.efi executed successfully. Exit Status: %r\n", Status);
    if (ExitDataSize > 0 && ExitData != NULL) {
      Print(L"  Exit Data: %s\n", ExitData);
      gBS->FreePool(ExitData); // Free the exit data if allocated by the launched app
    }
  }

  // Unload the image (optional, but good practice if you don't need it loaded anymore)
  // Be cautious: if the target app itself calls ExitBootServices, UnloadImage might fail.
  gBS->UnloadImage(TargetAppImageHandle);

  // Cleanup the device path if it was allocated
  if (TargetAppDevicePath != NULL) {
    FreePool(TargetAppDevicePath);
  }

  return EFI_SUCCESS;
}
#include <Protocol/DevicePathToText.h>
// Helper function to create a device path for a file relative to the current image's location
EFI_STATUS
LocateDevicePathForFile (
  IN  EFI_HANDLE                 ParentImageHandle,
  IN  CHAR16                     *FileName,
  OUT EFI_DEVICE_PATH_PROTOCOL   **DevicePath
  )
{
  EFI_STATUS                Status;
  EFI_LOADED_IMAGE_PROTOCOL *LoadedImage;
  EFI_DEVICE_PATH_PROTOCOL  *FileSystemDevicePath;
  EFI_DEVICE_PATH_PROTOCOL  *FileDevicePath;
  EFI_DEVICE_PATH_PROTOCOL  *Node;

  //CHAR16                        FileFullPath[256];
  CHAR16                          *DevicePathStr = NULL;
  EFI_DEVICE_PATH_FROM_TEXT_PROTOCOL *DevicePathFromText;
  EFI_DEVICE_PATH_TO_TEXT_PROTOCOL *DevicePathToText = NULL;

  Status = gBS->LocateProtocol(&gEfiDevicePathFromTextProtocolGuid, NULL, (VOID **)&DevicePathFromText);
  if (EFI_ERROR(Status)) {
    Print(L"EFI_DEVICE_PATH_FROM_TEXT_PROTOCOL Locate Protocol :%r \n", Status);
    return Status;

  }

  gBS->LocateProtocol(&gEfiDevicePathToTextProtocolGuid, NULL, (VOID**)&DevicePathToText);

//Status = gBS->OpenProtocol(
//                          ParentImageHandle,
//                          &gEfiLoadedImageProtocolGuid,
//                          (VOID **)&LoadedImage,
//                          ParentImageHandle,
//                          NULL,
//                          EFI_OPEN_PROTOCOL_GET_PROTOCOL
//    );


  Status = gBS->HandleProtocol(
                  ParentImageHandle,
                  &gEfiLoadedImageProtocolGuid,
                  (VOID **)&LoadedImage
                  );
  if (EFI_ERROR(Status)) {
    Print(L"OpenProtocol :%r \n", Status);
    return Status;
  }

  // Get the device path of the partition where this application is located
  FileSystemDevicePath = LoadedImage->FilePath;
  //DevicePathStr = DevicePathToText->ConvertDevicePathToText(FileSystemDevicePath, FALSE, FALSE);
  //Print(L"FileSystemDevicePathh str : %s \n" , DevicePathStr);
  if (FileSystemDevicePath == NULL) {
    Print(L"Get the device path of the partition where this application is locate not found\n");
    return EFI_NOT_FOUND; // Should not happen for a loaded image
  }

  // Traverse the device path to find the end (the file node)
  Node = FileSystemDevicePath;
  while (!IsDevicePathEnd(Node)) {
    Node = NextDevicePathNode(Node);
  }
  // Backtrack to the parent directory by removing the file node
  FileDevicePath = DuplicateDevicePath(FileSystemDevicePath);
  //DevicePathStr = DevicePathToText->ConvertDevicePathToText(FileDevicePath, FALSE, FALSE);
  //Print(L"FileDevicePath str : %s \n" , DevicePathStr);
  if (FileDevicePath == NULL) {
    Print(L"Backtrack to the parent directory by removing the file node EFI_OUT_OF_RESOURCES\n");
    return EFI_OUT_OF_RESOURCES;
  }
  SetDevicePathEndNode(Node); // Effectively truncate to parent directory path


//UnicodeSPrint(FileFullPath, sizeof(FileFullPath), L"%s%s%s",
//    L"\\", // Assuming root is the base, GRUB_EFI_PATH starts with '\'
//    L"PciRoot(0x0)/Pci(0x1D,0x3)/Pci(0x0,0x0)/NVMe(0x1,49-3B-A0-31-D8-38-25-00)/HD(1,GPT,AC396801-7980-4224-826F-21CBEC51728B,0x800,0x12C000)/",
//    FileName + 1 // Skip the leading '\'
//);
//
//
//Print(L"File Full Path : %s \n", FileFullPath);
//// Append the new file name

    // Convert text path to device path
  //*DevicePath = DevicePathFromText->ConvertTextToDevicePath(FileFullPath);
//
//DevicePathStr = DevicePathToText->ConvertDevicePathToText(*DevicePath, FALSE, FALSE);
//Print(L"Test Device Path str : %s \n" , DevicePathStr);
//  *DevicePath = (EFI_DEVICE_PATH_PROTOCOL *)DevicePathFromText->ConvertTextToDevicePath(FileName);
  *DevicePath = AppendDevicePathNode(FileDevicePath,
                                     (EFI_DEVICE_PATH_PROTOCOL *)DevicePathFromText->ConvertTextToDevicePath(FileName));
  FreePool(FileDevicePath); // Free the temporary device path

  DevicePathStr = DevicePathToText->ConvertDevicePathToText(*DevicePath, FALSE, FALSE);
  Print(L"Device Path str : %s \n" , DevicePathStr);
  if (*DevicePath == NULL) {
    Print(L"AppendDevicePathNode Nill\n");
    return EFI_OUT_OF_RESOURCES;
  }

  return EFI_SUCCESS;
}

// This is a conceptual C code snippet demonstrating how a UEFI application
// (like a simplified bootloader) would hand off control to a kernel.
// It is NOT runnable on its own and requires a UEFI development environment.


// Forward declarations for conceptual functions
EFI_STATUS LoadKernelIntoMemory(EFI_HANDLE ImageHandle, EFI_SYSTEM_TABLE *SystemTable, void **KernelEntryAddress, void **InitrdEntryAddress, UINTN *KernelSize, UINTN *InitrdSize);
void JumpToKernel(void *KernelEntry, EFI_MEMORY_DESCRIPTOR *MemoryMap, UINTN MapSize, UINTN DescriptorSize, void *InitrdAddress, UINTN InitrdSize, CHAR16 *CommandLine);

// Main entry point for the UEFI application
EFI_STATUS Load_Kernel(EFI_HANDLE ImageHandle, EFI_SYSTEM_TABLE *SystemTable) 
{
    //
    // 1. Initialize GNU-EFI library (for helper functions like Print)
    //    In a real scenario, you'd use direct UEFI services or your own wrappers.
    //
    //InitializeLib(ImageHandle, SystemTable);

    Print(L"UEFI Bootloader: Starting initialization...\n");

    //
    // 2. Obtain necessary UEFI services (already available via SystemTable here)
    //    A real bootloader would interact with various protocols like
    //    EFI_SIMPLE_FILE_SYSTEM_PROTOCOL to read the kernel from the ESP.
    //
    // EFI_GUID fsGuid = EFI_SIMPLE_FILE_SYSTEM_PROTOCOL_GUID;
    // EFI_SIMPLE_FILE_SYSTEM_PROTOCOL *fs;
    // SystemTable->BootServices->LocateProtocol(&fsGuid, NULL, (void**)&fs);
    // (Conceptual: assume filesystem access is set up to find the kernel)

    //
    // 3. (Conceptual) Load Kernel and Initramfs into memory
    //    In a real scenario, this involves:
    //    - Opening files on the EFI System Partition (ESP)
    //    - Reading file contents into allocated memory using BootServices->AllocatePages
    //    - Parsing kernel headers to find its entry point and requirements
    //
    void *KernelEntry = NULL;
    void *InitrdAddress = NULL;
    UINTN KernelSize = 0;
    UINTN InitrdSize = 0;

    EFI_STATUS Status = LoadKernelIntoMemory(ImageHandle, SystemTable, &KernelEntry, &InitrdAddress, &KernelSize, &InitrdSize);

    if (EFI_ERROR(Status)) {
        Print(L"UEFI Bootloader: Failed to load kernel! Status: %r\n", Status);
        // Loop indefinitely on error for debugging, or return.
        while (1);
    }

    Print(L"UEFI Bootloader: Kernel loaded successfully at %p.\n", KernelEntry);

    //
    // 4. Get the Memory Map
    //    This is crucial before calling ExitBootServices. The OS needs to know
    //    how memory is laid out and what regions are available.
    //
    EFI_MEMORY_DESCRIPTOR *MemoryMap = NULL;
    UINTN MapSize = 0;
    UINTN MapKey = 0;
    UINTN DescriptorSize = 0;
    UINT32 DescriptorVersion = 0;

    // First call to GetMemoryMap to get buffer size
    Status = SystemTable->BootServices->GetMemoryMap(&MapSize, MemoryMap, &MapKey, &DescriptorSize, &DescriptorVersion);
    if (Status == EFI_BUFFER_TOO_SMALL) {
        // Allocate buffer (add some margin)
        MapSize += EFI_PAGE_SIZE; // Add a page just in case for growth
        Status = SystemTable->BootServices->AllocatePool(EfiLoaderData, MapSize, (void**)&MemoryMap);
        if (EFI_ERROR(Status)) {
            Print(L"UEFI Bootloader: Failed to allocate memory map buffer! Status: %r\n", Status);
            while(1);
        }
        // Second call to GetMemoryMap to actually fill the buffer
        Status = SystemTable->BootServices->GetMemoryMap(&MapSize, MemoryMap, &MapKey, &DescriptorSize, &DescriptorVersion);
    }

    if (EFI_ERROR(Status)) {
        Print(L"UEFI Bootloader: Failed to get memory map! Status: %r\n", Status);
        // Free pool if allocated
        if (MemoryMap) SystemTable->BootServices->FreePool(MemoryMap);
        while (1);
    }

    Print(L"UEFI Bootloader: Memory Map obtained. MapKey: %d\n", MapKey);

    //
    // 5. Exit Boot Services (CRUCIAL HANDOVER)
    //    This tells the UEFI firmware that the OS is taking over. After this,
    //    most UEFI services are no longer available.
    //
    Print(L"UEFI Bootloader: Calling ExitBootServices()...\n");
    Status = SystemTable->BootServices->ExitBootServices(ImageHandle, MapKey);

    if (EFI_ERROR(Status)) {
        // If ExitBootServices fails, we are in a bad state.
        // This usually means the memory map key is invalid (e.g., memory map changed).
        // A robust bootloader would retry getting the memory map and calling ExitBootServices.
        Print(L"UEFI Bootloader: ExitBootServices FAILED! Status: %r\n", Status);
        // Cannot use Print after a failed ExitBootServices in a real scenario,
        // as print services are usually boot services. This is for conceptual demo.
        while (1);
    }

    Print(L"UEFI Bootloader: Successfully exited Boot Services. Jumping to kernel...\n");

    //
    // 6. Jump to Kernel Entry Point
    //    This is the final step. The bootloader performs a direct jump
    //    to the kernel's starting address.
    //    The kernel will then use the provided memory map and parameters
    //    to initialize itself.
    //
    CHAR16 *CommandLine = L"root=/dev/sdaX quiet splash"; // Example kernel command line
    JumpToKernel(KernelEntry, MemoryMap, MapSize, DescriptorSize, InitrdAddress, InitrdSize, CommandLine);

    // This part should never be reached if JumpToKernel is successful
    return EFI_SUCCESS;
}


// --- Conceptual Helper Functions (Simplified, no actual implementation) ---

// Helper function to load a file from the ESP into memory
// This is a simplified version and lacks robust error handling and path discovery.
EFI_STATUS LoadFileFromEsp(
    EFI_SYSTEM_TABLE *SystemTable,
    EFI_HANDLE ImageHandle,
    CHAR16 *FileName,
    void **FileData,
    UINTN *FileSize) 
{

    EFI_STATUS Status;
    EFI_LOADED_IMAGE_PROTOCOL *LoadedImage;
    EFI_SIMPLE_FILE_SYSTEM_PROTOCOL *FileSystem;
    EFI_FILE_PROTOCOL *Root, *FileHandle;
    UINTN ReadSize;

    Print(L"  Attempting to load file: %s\n", FileName);

    // Get the EFI_LOADED_IMAGE_PROTOCOL for the current image
    Status = SystemTable->BootServices->HandleProtocol(
        ImageHandle,
        &gEfiLoadedImageProtocolGuid,
        (void**)&LoadedImage
    );
    if (EFI_ERROR(Status)) {
        Print(L"  Failed to get LoadedImageProtocol: %r\n", Status);
        return Status;
    }

    // Get the EFI_SIMPLE_FILE_SYSTEM_PROTOCOL from the device handle of the loaded image
    Status = SystemTable->BootServices->HandleProtocol(
        LoadedImage->DeviceHandle,
        &gEfiSimpleFileSystemProtocolGuid,
        (void**)&FileSystem
    );
    if (EFI_ERROR(Status)) {
        Print(L"  Failed to get FileSystemProtocol: %r\n", Status);
        return Status;
    }

    // Open the root directory of the file system
    Status = FileSystem->OpenVolume(FileSystem, &Root);
    if (EFI_ERROR(Status)) {
        Print(L"  Failed to open volume: %r\n", Status);
        return Status;
    }

    // Open the file
    Status = Root->Open(Root, &FileHandle, FileName, EFI_FILE_MODE_READ, 0);
    if (EFI_ERROR(Status)) {
        Print(L"  Failed to open file %s: %r\n", FileName, Status);
        Root->Close(Root); // Close root even if file open fails
        return Status;
    }

    // Get file info to determine size
    EFI_FILE_INFO *FileInfo;
    UINTN FileInfoSize = 0;

    Status = FileHandle->GetInfo(FileHandle, &gEfiFileInfoGuid, &FileInfoSize, NULL);
    if (Status == EFI_BUFFER_TOO_SMALL) {
        Status = SystemTable->BootServices->AllocatePool(EfiLoaderData, FileInfoSize, (void**)&FileInfo);
        if (EFI_ERROR(Status)) {
            Print(L"  Failed to allocate FileInfo buffer: %r\n", Status);
            FileHandle->Close(FileHandle);
            Root->Close(Root);
            return Status;
        }
        Status = FileHandle->GetInfo(FileHandle, &gEfiFileInfoGuid, &FileInfoSize, FileInfo);
    }

    if (EFI_ERROR(Status)) {
        Print(L"  Failed to get file info: %r\n", Status);
        if (FileInfo) SystemTable->BootServices->FreePool(FileInfo);
        FileHandle->Close(FileHandle);
        Root->Close(Root);
        return Status;
    }

    *FileSize = FileInfo->FileSize;
    SystemTable->BootServices->FreePool(FileInfo); // Free FileInfo buffer

    // Allocate memory for the file content
    Status = SystemTable->BootServices->AllocatePages(AllocateAnyPages, EfiLoaderData, EFI_SIZE_TO_PAGES(*FileSize), (EFI_PHYSICAL_ADDRESS*)FileData);
    if (EFI_ERROR(Status)) {
        Print(L"  Failed to allocate pages for file data: %r\n", Status);
        FileHandle->Close(FileHandle);
        Root->Close(Root);
        return Status;
    }

    // Read the file content
    ReadSize = *FileSize;
    Status = FileHandle->Read(FileHandle, &ReadSize, *FileData);
    if (EFI_ERROR(Status)) {
        Print(L"  Failed to read file data: %r\n", Status);
        SystemTable->BootServices->FreePages((EFI_PHYSICAL_ADDRESS)*FileData, EFI_SIZE_TO_PAGES(*FileSize));
        FileHandle->Close(FileHandle);
        Root->Close(Root);
        return Status;
    }

    Print(L"  File %s loaded successfully. Size: %ld bytes.\n", FileName, *FileSize);

    FileHandle->Close(FileHandle);
    Root->Close(Root);

    return EFI_SUCCESS;
}


EFI_STATUS LoadKernelIntoMemory(
    EFI_HANDLE ImageHandle,
    EFI_SYSTEM_TABLE *SystemTable,
    void **KernelEntryAddress,
    void **InitrdEntryAddress,
    UINTN *KernelSize,
    UINTN *InitrdSize) {

    EFI_STATUS Status;

    Print(L"  Loading kernel and initramfs...\n");

    // Load Kernel (example path, adjust as needed for your setup)
    // Common paths: \EFI\LINUX\vmlinuz, \vmlinuz-linux, etc.
    Status = LoadFileFromEsp(SystemTable, ImageHandle, L"\\efi\\rocky\vmlinuz", KernelEntryAddress, KernelSize);
    if (EFI_ERROR(Status)) {
        Print(L"  Failed to load kernel file!\n");
        return Status;
    }

    // Load Initramfs (example path, adjust as needed)
    // Common paths: \EFI\LINUX\initramfs-linux.img, \initrd.img, etc.
    Status = LoadFileFromEsp(SystemTable, ImageHandle, L"\\SSBL.efi", InitrdEntryAddress, InitrdSize);
    if (EFI_ERROR(Status)) {
        Print(L"  Failed to load initramfs file!\n");
        // Free kernel memory if initramfs fails to load
        SystemTable->BootServices->FreePages((EFI_PHYSICAL_ADDRESS)*KernelEntryAddress, EFI_SIZE_TO_PAGES(*KernelSize));
        return Status;
    }

    // For a Linux kernel with EFI stub, the entry point is typically the start of the loaded image.
    // For other boot protocols, you might need to parse the file for the actual entry point.

    return EFI_SUCCESS;
}

// Function to perform the jump to the kernel
// This function would typically involve architecture-specific assembly code
// to set up registers and then jump to the kernel's entry point.
// In a real bootloader, this function would NOT return.
void JumpToKernel(
    void *KernelEntry,
    EFI_MEMORY_DESCRIPTOR *MemoryMap,
    UINTN MapSize,
    UINTN DescriptorSize,
    void *InitrdAddress,
    UINTN InitrdSize,
    CHAR16 *CommandLine) {

    Print(L"  (Conceptual) Performing final jump to kernel at %p...\n", KernelEntry);
    Print(L"  (Conceptual) Kernel Command Line: %s\n", CommandLine);
    Print(L"  (Conceptual) Memory Map Address: %p, Size: %ld, Descriptor Size: %ld\n", MemoryMap, MapSize, DescriptorSize);
    Print(L"  (Conceptual) Initrd Address: %p, Size: %ld\n", InitrdAddress, InitrdSize);

    // --- REAL IMPLEMENTATION for x86-64 Linux kernel would involve: ---
    // 1. Disable interrupts.
    //    asm volatile ("cli");
    // 2. Load the GDT (Global Descriptor Table) and IDT (Interrupt Descriptor Table)
    //    for the kernel's execution environment.
    // 3. Set up CPU registers according to the Linux x86_64 boot protocol:
    //    - RDI: Address of the EFI System Table (or a custom boot info structure)
    //    - RSI: Address of the memory map (EFI_MEMORY_DESCRIPTOR array)
    //    - RDX: Size of the memory map in bytes (MapSize)
    //    - RCX: Size of a single memory map descriptor in bytes (DescriptorSize)
    //    - R8: Address of the initial RAM disk (initramfs)
    //    - R9: Size of the initial RAM disk (initramfs)
    //    - For the kernel command line, it's typically a pointer to the string.
    //      The exact register for command line might vary or be passed via a boot info struct.
    // 4. Perform a direct assembly jump to the kernel's entry point:
    //    ((void (*)(void))KernelEntry)();
    //    Or more explicitly with parameters (simplified, as C function calls handle this
    //    differently than a direct jump to an OS kernel entry):
    //    asm volatile (
    //        "mov %0, %%rdi\n" // Pass SystemTable or custom boot info
    //        "mov %1, %%rsi\n" // Pass MemoryMap
    //        "mov %2, %%rdx\n" // Pass MapSize
    //        "mov %3, %%rcx\n" // Pass DescriptorSize
    //        "mov %4, %%r8\n"  // Pass InitrdAddress
    //        "mov %5, %%r9\n"  // Pass InitrdSize
    //        "jmp *%6\n"       // Jump to KernelEntry
    //        : // No output operands
    //        : "r" (SystemTable), "r" (MemoryMap), "r" (MapSize), "r" (DescriptorSize),
    //          "r" (InitrdAddress), "r" (InitrdSize), "r" (KernelEntry)
    //        : "rdi", "rsi", "rdx", "rcx", "r8", "r9" // Clobbered registers
    //    );

    // In a real scenario, execution would never return from here.
    // We add an infinite loop here only for conceptual demonstration
    // within an environment that doesn't execute actual low-level code.
    while(1);
}


SBCStatus  LoadAndStartMemoryImage(VOID *handle, VOID *imgbuf, UINTN imglen)
{
    SBCStatus ret = SBCOK;

    EFI_STATUS                 retval;
    EFI_HANDLE                 LoadedImageHandle = NULL;
    MEMMAP_DEVICE_PATH         MemoryDevicePath;
    EFI_DEVICE_PATH_PROTOCOL   *EndOfDevicePath;
    EFI_LOADED_IMAGE_PROTOCOL  *LoadedImage = NULL;

    SBC_RET_VALIDATE_ERRCODEMSG((imgbuf != NULL), SBCNULLP, "Image Bufrfe Nill");

    dprint( "Attempting to load image from memory at 0x%lx, size 0x%lx\n", (UINTN)imgbuf, imglen);


    // Create the memory-mapped device path

    MemoryDevicePath.Header.Type      = MEDIA_DEVICE_PATH;
    MemoryDevicePath.Header.SubType   = MEDIA_HARDDRIVE_DP;

    // + EOD
    SetDevicePathNodeLength (&MemoryDevicePath.Header, 
                             sizeof(MEMMAP_DEVICE_PATH) + sizeof(EFI_DEVICE_PATH_PROTOCOL)); 

    MemoryDevicePath.MemoryType      = EfiLoaderCode; // Or EfiBootServicesCode, EfiRuntimeServicesCode, etc.
                                                      // EfiLoaderCode is often appropriate for applications/drivers.

    MemoryDevicePath.StartingAddress = (EFI_PHYSICAL_ADDRESS)(UINTN)imgbuf;
    MemoryDevicePath.EndingAddress   = (EFI_PHYSICAL_ADDRESS)((UINTN)imgbuf + imglen - 1);

    dprint("Starting Address original : 0x%lx , Assign : 0x%lx , Ending Addr  : 0x%lx", 
           imgbuf, MemoryDevicePath.StartingAddress, MemoryDevicePath.EndingAddress);

    // Append the End-Of-Device-Path node
    EndOfDevicePath = (EFI_DEVICE_PATH_PROTOCOL *)((UINTN)&MemoryDevicePath + sizeof(MEMMAP_DEVICE_PATH));
    SetDevicePathEndNode (EndOfDevicePath);

    retval = gBS->LoadImage(
                  FALSE,                 // BootPolicy: FALSE for driver/application, TRUE for OS loader
                  gImageHandle,           // ParentImageHandle: The handle of the image calling LoadImage
                  (EFI_DEVICE_PATH_PROTOCOL *)&MemoryDevicePath, // FilePath (our memory device path)
                  imgbuf, // SourceBuffer: Pointer to the in-memory image
                  imglen,   // SourceSize: Size of the in-memory image
                  &LoadedImageHandle     // Output: Handle for the newly loaded image
                  );


    if (EFI_ERROR(retval)) {
      eprint("LoadImage from memory failed: %r\n", retval);
      ret = SBCFAIL;
      goto errdone;
    }

    dprint( "Image loaded successfully from memory. New handle: 0x%lx\n", (UINTN)LoadedImageHandle);

    // Verify the EFI_LOADED_IMAGE_PROTOCOL on the new handle
    retval = gBS->OpenProtocol(
        LoadedImageHandle,
        &gEfiLoadedImageProtocolGuid,
        (VOID **)&LoadedImage,
        gImageHandle,
        NULL,
        EFI_OPEN_PROTOCOL_GET_PROTOCOL
        );

    if (!EFI_ERROR(retval)) {
        dprint( "Loaded Image Base Address: 0x%lx, Size: 0x%lx\n", (UINTN)LoadedImage->ImageBase, (UINTN)LoadedImage->ImageSize);
        dprint( "Loaded Image Device Path Type: %d, SubType: %d\n", LoadedImage->FilePath->Type, LoadedImage->FilePath->SubType);
        // Close the protocol handle if we only needed to peek
        gBS->CloseProtocol (
               LoadedImageHandle,
               &gEfiLoadedImageProtocolGuid,
               gImageHandle,
               NULL
               );
    } else {
        eprint("Failed to open EFI_LOADED_IMAGE_PROTOCOL on new handle: %r\n", retval);
        ret = SBCFAIL;
        goto errdone;
    }
   

    // Start the loaded image
    retval = gBS->StartImage (LoadedImageHandle, NULL, NULL);

    if (EFI_ERROR(retval)) {
      eprint( "StartImage failed: %r\n", retval);
      // Unload the image if starting failed
      gBS->UnloadImage (LoadedImageHandle);
      ret = SBCFAIL;
      goto errdone;
    } else {
      dprint( "Image started and returned successfully.\n");
    }

    //
    // Unload the image when no longer needed (optional, depending on its purpose)
    //
    // If the started image is an application that returned, you might unload it.
    // If it's a driver that installs protocols, you might keep it loaded.
    //
    

    retval = gBS->UnloadImage (LoadedImageHandle);
    if (EFI_ERROR(retval)) {
      eprint( "UnloadImage failed: %r\n", retval);
      ret = SBCFAIL;
      goto errdone;
    } else {
      dprint( "Image unloaded successfully.\n");
    }

    //ret = SBCOK;
errdone:
    return ret;

}

