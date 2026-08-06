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
#include "SBC_AntiTampering.h"

// Define the path to grubx64.efi relative to the root of the file system
// Adjust this path if your grubx64.efi is located elsewhere (e.g., "\EFI\ubuntu\grubx64.efi")
#define GRUB_EFI_PATH L"\\EFI\\rocky\\grubx64.efi"


EFI_STATUS
SBC_ConnectAllEfi (
  VOID
  )
{
  EFI_STATUS  Status;
  UINTN       HandleCount;
  EFI_HANDLE  *HandleBuffer;
  UINTN       Index;

  Status = gBS->LocateHandleBuffer (
                  AllHandles,
                  NULL,
                  NULL,
                  &HandleCount,
                  &HandleBuffer
                  );
  if (EFI_ERROR (Status)) {
    return Status;
  }

  for (Index = 0; Index < HandleCount; Index++) {
    Status = gBS->ConnectController (HandleBuffer[Index], NULL, NULL, TRUE);
  }

  if (HandleBuffer != NULL) {
    FreePool (HandleBuffer);
  }

  return EFI_SUCCESS;
}

/*!
 * \fn EFI_STATUS SBC_LodaDriver(CONST CHAR16 *FileName, CONST BOOLEAN  Connect)
 * 
 * Function to Load a .EFI driver into memory and possible connect the driver 
 * 
 * \author leoc (8/12/25)
 * 
 * \param FileName File name of the driver to load
 * \param Connect  Not yet support 
 * 
 * \return On success, return the EFI_SUCCESS, otherwise, it is ERROR 
 */
EFI_STATUS SBC_LodaDriver(CONST CHAR16 *FileName, CONST BOOLEAN  Connect)
{
  EFI_HANDLE                 LoadedDriverHandle;
  EFI_HANDLE *Handles;
  UINTN HandleCount;
  [[maybe_unused]]EFI_STATUS                 Status;
  EFI_DEVICE_PATH_PROTOCOL   *DevicePath;
  [[maybe_unused]]EFI_LOADED_IMAGE_PROTOCOL  *LoadedDriverImage;
  CHAR16 *PathStr;

  LoadedDriverImage  = NULL;
  DevicePath           = NULL;
  LoadedDriverHandle = NULL;
  Status             = EFI_SUCCESS;

  ASSERT (FileName != NULL);

  gBS->LocateHandleBuffer(ByProtocol, 
                          &gEfiSimpleFileSystemProtocolGuid, 
                          NULL, 
                          &HandleCount, 
                          &Handles);

  //for (UINTN i = 0; i < HandleCount; i++) {
 
    DevicePath = FileDevicePath(Handles[0], FileName);
//    DevicePath = FileDevicePath(Handles[i], L"\\EFI\\BOOT\\SSBLFactory.efi");
    PathStr = ConvertDevicePathToText(DevicePath, TRUE, TRUE);
    if (PathStr != NULL) {
      Print(L"Device Path: %s\n", PathStr);
      FreePool(PathStr);
    } else {
      Print(L"Failed to convert device path to string.\n");
      //return SBCFAIL;
    }
    Status = gBS->LoadImage(FALSE, 
                                       gImageHandle, 
                                       DevicePath, 
                                       NULL, 
                                       0, 
                                       &LoadedDriverHandle);

    if (Status == EFI_SECURITY_VIOLATION) {
      gBS->UnloadImage (LoadedDriverHandle);
     Print(L"Image '%s' is not an image \r\n",  FileName);
    }

    if (!EFI_ERROR(Status)) {
      Status = gBS->HandleProtocol (LoadedDriverHandle, &gEfiLoadedImageProtocolGuid, (VOID *)&LoadedDriverImage);
      ASSERT (LoadedDriverImage != NULL);

      if (  EFI_ERROR (Status)
         || (  (LoadedDriverImage->ImageCodeType != EfiBootServicesCode)
            && (LoadedDriverImage->ImageCodeType != EfiRuntimeServicesCode))
            )
      {
        Print(L"Image '%s' is not a driver \r\n",  FileName);

        //
        // Exit and unload the non-driver image
        //
        gBS->Exit (LoadedDriverHandle, EFI_INVALID_PARAMETER, 0, NULL);
        Status = EFI_INVALID_PARAMETER;
      }
    }

    if (!EFI_ERROR(Status)) {
      Status = gBS->StartImage(LoadedDriverHandle, NULL, NULL);
      if (EFI_ERROR (Status)) {
        Print(L"Imasge '%s' error in StartImage: %r \r\n", FileName, Status);
      }
      else {
        Print(L"Image '%s' loaded at %p - %r \r\n", 
              FileName,
              LoadedDriverImage->ImageBase,
              Status );
        //return SBCOK;
      }

    }
  //}

    if (!EFI_ERROR (Status) && Connect) {
      Status = SBC_ConnectAllEfi();
    }


    Print(L"Last status : %r \r\n", Status);


  return Status;

}



/**
 * @fn SBC_GRUB_LoadAndStart
 * @brief Locate, load, and start the GRUB EFI image (grubx64.efi) from an EFI filesystem.
 *
 * This function enumerates all handles that support Simple File System (SimpleFS),
 * builds a device path to "\\EFI\\rocky\\grubx64.efi" for each handle, attempts to
 * LoadImage(), and starts the first successfully loaded GRUB image via StartImage().
 *
 * @param[in] ImageHandle
 *      Image handle variable used as an OUT target for LoadImage().
 *      (Note: Current signature passes by value; only used internally after LoadImage.)
 *
 * @retval SBCOK
 *      Function returns SBCOK regardless of whether GRUB was actually started
 *      in the current implementation.
 *
 * @details
 * Processing steps:
 *
 * Step 1. Locate all handles that support <code>EFI_SIMPLE_FILE_SYSTEM_PROTOCOL</code>
 *         via <code>gBS->LocateHandleBuffer(ByProtocol, ...)</code>.
 *
 * Step 2. Emit a log message indicating GRUB loading is starting.
 *
 * Step 3. For each SimpleFS handle:
 *         <ol>
 *           <li>Create a device path to <code>"\\EFI\\rocky\\grubx64.efi"</code>
 *               using <code>FileDevicePath()</code>.</li>
 *           <li>Convert the device path to text with <code>ConvertDevicePathToText()</code>
 *               and print it for debugging.</li>
 *           <li>Attempt to load the image with <code>gBS->LoadImage()</code>.</li>
 *           <li>If load succeeds, start it with <code>gBS->StartImage()</code> and stop searching.</li>
 *         </ol>
 *
 * Step 4. Return <code>SBCOK</code>.
 *
 * @note
 * - Current implementation does not check the return status of LocateHandleBuffer()
 *   and does not free the handle buffer (<code>Handles</code>) on exit.
 * - The created <code>DevicePath</code> may need to be freed depending on implementation.
 * - The function always returns <code>SBCOK</code>, even if GRUB was not found or failed
 *   to load/start. Consider returning an error when all attempts fail.
 * - Parameter name <code>ImageHandle</code> shadows the global <code>gImageHandle</code>
 *   conceptually; ensure there is no confusion between "current image handle" and
 *   "loaded grub image handle".
 */
SBCStatus SBC_GRUB_LoadAndStart(EFI_HANDLE ImageHandle)
{
  EFI_HANDLE *Handles;
  UINTN HandleCount;
  //EFI_SIMPLE_FILE_SYSTEM_PROTOCOL *Fs;
  EFI_DEVICE_PATH_PROTOCOL *DevicePath;
  //EFI_HANDLE imghandle;
  CHAR16 *PathStr;

  gBS->LocateHandleBuffer(ByProtocol, &gEfiSimpleFileSystemProtocolGuid, NULL, &HandleCount, &Handles);


  sbc_err_sysprn(SBC_LOG_CMN_PRIO_NOTICE, 2, 
            SYS_LOG_HOST_BOOT, 
            SYS_LOG_APP_NAME, 
            SYS_LOG_CSC_NAME, 
            8, 
            L"Validation ", 
            L"GCS_VENDOR_SP Grub Loading !!!");  

 #ifdef _LOG_RECODING_
    SBC_LogDeinit(&gLogCtx);
#endif
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


