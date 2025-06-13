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
  DEBUG ((DEBUG_INFO, "GrubLauncherApp: EntryPoint.\n"));

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
    DEBUG ((DEBUG_ERROR, "GrubLauncherApp: LocateHandleBuffer failed: %r\n", Status));
    return Status;
  }

  //
  // 2. Iterate through each found file system handle.
  //
  for (Index = 0; Index < NumHandles; Index++) {
    Print(L"GrubLauncherApp: Checking FS%d...\n", Index);
    DEBUG ((DEBUG_INFO, "GrubLauncherApp: Checking handle %p.\n", ControllerHandleBuffer[Index]));

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
      DEBUG ((DEBUG_ERROR, "GrubLauncherApp: Failed to open Simple File System Protocol on handle %p: %r\n", ControllerHandleBuffer[Index], Status));
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
      DEBUG ((DEBUG_ERROR, "GrubLauncherApp: Failed to open volume on handle %p: %r\n", ControllerHandleBuffer[Index], Status));
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
      DEBUG ((DEBUG_INFO, "GrubLauncherApp: %s not found on FS%d: %r\n", GRUB_EFI_PATH, Index, Status));
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
      DEBUG ((DEBUG_ERROR, "GrubLauncherApp: Failed to get device path protocol for handle %p: %r\n", ControllerHandleBuffer[Index], Status));
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
    DEBUG ((DEBUG_INFO, "GrubLauncherApp: Calling LoadImage with %s.\n", GRUB_EFI_PATH));

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
      DEBUG ((DEBUG_ERROR, "GrubLauncherApp: LoadImage failed for %s: %r\n", GRUB_EFI_PATH, Status));
      // Close resources and try next FS if LoadImage fails
      GrubFile->Close(GrubFile);
      Root->Close(Root);
      continue;
    }

    Print(L"GrubLauncherApp: %s loaded successfully. Starting...\n", GRUB_EFI_PATH);
    DEBUG ((DEBUG_INFO, "GrubLauncherApp: Starting loaded GRUB image.\n"));

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
      DEBUG ((DEBUG_ERROR, "GrubLauncherApp: StartImage failed for %s: %r\n", GRUB_EFI_PATH, Status));
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
  DEBUG ((DEBUG_ERROR, "GrubLauncherApp: %s not found.\n", GRUB_EFI_PATH));

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

  // 1. Get the device path to the target EFI executable
  // Assuming TargetApp.efi is in the same directory as MyLauncher.efi
  Status = LocateDevicePathForFile(ImageHandle, L"\\EFI\\boot\\SSBL.efi", &TargetAppDevicePath);
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


  EFI_DEVICE_PATH_FROM_TEXT_PROTOCOL *DevicePathFromText;

  gBS->LocateProtocol(&gEfiDevicePathFromTextProtocolGuid, NULL, (VOID **)&DevicePathFromText);


  Status = gBS->HandleProtocol(
                  ParentImageHandle,
                  &gEfiLoadedImageProtocolGuid,
                  (VOID **)&LoadedImage
                  );
  if (EFI_ERROR(Status)) {
    return Status;
  }

  // Get the device path of the partition where this application is located
  FileSystemDevicePath = LoadedImage->FilePath;
  if (FileSystemDevicePath == NULL) {
    return EFI_NOT_FOUND; // Should not happen for a loaded image
  }

  // Traverse the device path to find the end (the file node)
  Node = FileSystemDevicePath;
  while (!IsDevicePathEnd(Node)) {
    Node = NextDevicePathNode(Node);
  }
  // Backtrack to the parent directory by removing the file node
  FileDevicePath = DuplicateDevicePath(FileSystemDevicePath);
  if (FileDevicePath == NULL) {
    return EFI_OUT_OF_RESOURCES;
  }
  SetDevicePathEndNode(Node); // Effectively truncate to parent directory path

  // Append the new file name
  *DevicePath = AppendDevicePathNode(FileDevicePath, 
                                     (EFI_DEVICE_PATH_PROTOCOL *)DevicePathFromText->ConvertTextToDevicePath(FileName));
  FreePool(FileDevicePath); // Free the temporary device path

  if (*DevicePath == NULL) {
    return EFI_OUT_OF_RESOURCES;
  }

  return EFI_SUCCESS;
}
