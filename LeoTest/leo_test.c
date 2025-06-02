/** @file
  Brief Description of UEFI MyHelloWorld
  Detailed Description of UEFI MyHelloWorld
  Copyright for UEFI MyHelloWorld
  License for UEFI MyHelloWorld
**/


#include <Uefi.h>
#include <Library/PcdLib.h>
#include <Library/UefiLib.h>
#include <Library/UefiApplicationEntryPoint.h>
//#include <Libray/RngLib.h>

#include <Library/BaseLib.h>
//#include <Library/CtLibSuppot.h>
#include <Library/BaseCryptLib.h>
#include <Library/BaseMemoryLib.h>
#include <malloc.h>
#include <Register/Intel/Cpuid.h>

#include <Library/ShellLib.h>
#include <Library/MemoryAllocationLib.h>
#include <Protocol/Smbios.h>


#include <string.h>
#include <stdio.h>
#include <stdlib.h>

// Block Io
#include <Protocol/BlockIo.h>
#include <Protocol/DiskInfo.h>
#include <Protocol/SerialIo.h>
// Serial 
#include <Library/SerialPortLib.h>
#include <Library/PcdLib.h>
#include "leo_test.h"
// Length value


#include <Library/UefiBootServicesTableLib.h>
#include <Library/FileHandleLib.h>

#include <Protocol/Smbios.h>

#include <Library/UnitTestLib.h>


#include <openssl/objects.h>
#include <openssl/bn.h>
#include <openssl/ec.h>

#include "SBC_Log.h"
#include "SBC_ErrorType.h"
#include "SBC_CryptAES.h"
#include "SBC_FileCtrl.h"
#include "SBC_TypeDefs.h"
#include "SBC_EccSignVerify.h"
#include "SBC_Config.h"


#ifdef LEO_EMUPKG
RETURN_STATUS EFIAPI SerialPortInitialize(VOID)
{
  RETURN_STATUS ret = RETURN_SUCCESS;

  UINT64              BaudRate;
  UINT32              ReceiveFifoDepth;
  EFI_PARITY_TYPE     Parity;
  UINT8               DataBits;
  EFI_STOP_BITS_TYPE  StopBits;

  BaudRate         = FixedPcdGet64 (PcdUartDefaultBaudRate);
  ReceiveFifoDepth = 0;         // Use default FIFO depth
  Parity           = (EFI_PARITY_TYPE)FixedPcdGet8 (PcdUartDefaultParity);
  DataBits         = FixedPcdGet8 (PcdUartDefaultDataBits);
  StopBits         = (EFI_STOP_BITS_TYPE)FixedPcdGet8 (PcdUartDefaultStopBits);


  dprint("----- SerialProtInitialize -----");
  dprint("Baud Rate : %d", BaudRate);
  dprint("ReceiveFifoDepth : %d", ReceiveFifoDepth);
  dprint("Parity : %d", (UINT32)Parity);
  dprint("DataBits : %d", (UINT32)DataBits);
  dprint("StopBits : %d", (UINT32)StopBits);

  return ret;
}
#endif

#include <Library/HandleParsingLib.h>

VOID  get_blokio_handleparse(VOID)
{
  EFI_HANDLE    *HandleList;
  EFI_HANDLE    *HandleListWalker;
  CHAR16        *Name;
  CONST CHAR16  *Lang = L"EN";
  CHAR8         *Language;
  CHAR8         DeviceName[512];

  HandleList = GetHandleListByProtocol(&gEfiBlockIoProtocolGuid);
  if(HandleList == NULL) {
    Print(L"GetHandleListByProtocol Nill \n" );
    goto errdone;

  }

  Language = AllocateZeroPool(StrSize(Lang));
  AsciiSPrint(Language, StrSize(Lang), "%S", Lang);
  for(HandleListWalker = HandleList
      ; HandleListWalker != NULL && *HandleListWalker != NULL
      ; HandleListWalker++) {
    Name = NULL;
    gEfiShellProtocol->GetDeviceName(*HandleListWalker
                                     ,EFI_DEVICE_NAME_USE_COMPONENT_NAME|EFI_DEVICE_NAME_USE_DEVICE_PATH
                                     ,(CHAR8 *)Language, &Name);


    ZeroMem(DeviceName, sizeof DeviceName);
    AsciiSPrint(DeviceName, StrSize(Name), "%S", Name);

    SBC_mem_print_bin("Deviec Name", (UINT8 *)DeviceName, 16);

    


  }


errdone:

}


EFI_STATUS _get_directory_and_file(VOID)
{
  
  EFI_STATUS                          Status;
  EFI_HANDLE                          *HandleBuffer;
  UINTN                               NumberOfHandles;
  EFI_SIMPLE_FILE_SYSTEM_PROTOCOL     *SimpleFileSystem;
  EFI_FILE_PROTOCOL                   *Root;
  EFI_FILE_INFO                       *FileInfo;
  UINTN                               FileInfoSize;

  // Locate all Simple File System Protocol instances
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

  // Iterate through found file systems
  for (UINTN Index = 0; Index < NumberOfHandles; Index++) {
    Status = gBS->HandleProtocol (
                    HandleBuffer[Index],
                    &gEfiSimpleFileSystemProtocolGuid,
                    (VOID **)&SimpleFileSystem
                    );
    if (EFI_ERROR (Status)) {
      Print(L"Failed to get Simple File System Protocol from handle: %r\n", Status);
      continue;
    }

    // Open the root volume
    Status = SimpleFileSystem->OpenVolume (
                                 SimpleFileSystem,
                                 &Root
                                 );
    if (EFI_ERROR (Status)) {
      Print(L"Failed to open file system volume: %r\n", Status);
      continue;
    }

    Print(L"\n--- Listing contents of a file system ---\n");

    // Allocate a buffer for file info (adjust size as needed)
    FileInfoSize = sizeof(EFI_FILE_INFO) + 256; // Max path length + struct size
    Status = gBS->AllocatePool (
                    EfiBootServicesData,
                    FileInfoSize,
                    (VOID **)&FileInfo
                    );
    if (EFI_ERROR (Status)) {
      Print(L"Failed to allocate memory for file info: %r\n", Status);
      Root->Close(Root);
      continue;
    }

    // Read directory entries
    while (TRUE) {
      UINTN   ReadSize = FileInfoSize;
      Status = Root->Read (
                       Root,
                       &ReadSize,
                       FileInfo
                       );

      if (EFI_ERROR (Status) || ReadSize == 0) {
        break; // End of directory or error
      }

      // Print file/directory name and attributes
      Print(L"%s %s\n",
            (FileInfo->Attribute & EFI_FILE_DIRECTORY) ? L"<DIR>" : L"     ",
            FileInfo->FileName
            );
    }

    gBS->FreePool (FileInfo);
    Root->Close(Root); // Close the root directory handle
  }

  gBS->FreePool (HandleBuffer);
  return EFI_SUCCESS;

}

#include <Protocol/DevicePathToText.h>
EFI_STATUS test_deivce_paht_string(EFI_HANDLE ImageHandle)
{
    EFI_STATUS                      Status;
  EFI_LOADED_IMAGE_PROTOCOL       *LoadedImage;
  EFI_DEVICE_PATH_PROTOCOL        *DevicePath = NULL;
  EFI_DEVICE_PATH_TO_TEXT_PROTOCOL *DevicePathToText = NULL;
  CHAR16                          *DevicePathStr = NULL;

  //
  // 1. Open the Loaded Image Protocol on your own ImageHandle
  //
  Status = gBS->OpenProtocol (
                  ImageHandle,
                  &gEfiLoadedImageProtocolGuid,
                  (VOID **)&LoadedImage,
                  ImageHandle,
                  NULL,
                  EFI_OPEN_PROTOCOL_GET_PROTOCOL
                  );

  if (EFI_ERROR (Status)) {
    Print(L"ERROR: Failed to open LoadedImageProtocol on ImageHandle: %r\n", Status);
    return Status;
  }

  Print(L"Successfully opened LoadedImageProtocol.\n");
  Print(L"Image Base: 0x%p\n", LoadedImage->ImageBase);
  Print(L"Image Size: 0x%llx\n", LoadedImage->ImageSize);

  //
  // 2. Get the Device Path from the Loaded Image Protocol
  //    The FilePath member of EFI_LOADED_IMAGE_PROTOCOL is an EFI_DEVICE_PATH_PROTOCOL
  //    that describes the location from which the image was loaded.
  //
  DevicePath = LoadedImage->FilePath;

  if (DevicePath == NULL) {
    Print(L"WARNING: LoadedImage->FilePath is NULL. Cannot get device path string.\n");
    return EFI_NOT_FOUND;
  }

  //
  // 3. Locate the EFI_DEVICE_PATH_TO_TEXT_PROTOCOL
  //    This protocol provides the function to convert the binary device path
  //    into a human-readable string.
  //
  Status = gBS->LocateProtocol (
                  &gEfiDevicePathToTextProtocolGuid, // The GUID of the protocol to locate
                  NULL,                                // No registration context needed
                  (VOID **)&DevicePathToText          // Pointer to receive the protocol interface
                  );

  if (EFI_ERROR (Status)) {
    Print(L"ERROR: Failed to locate DevicePathToTextProtocol: %r\n", Status);
    // You can still return success, just won't print the path
    return Status;
  }

  //
  // 4. Convert the Device Path to a human-readable string
  //    The ConvertDevicePathToText function allocates a buffer for the string
  //    which you must later free using FreePool.
  //
  DevicePathStr = DevicePathToText->ConvertDevicePathToText (
                                      DevicePath,
                                      FALSE, // DisplayOnly: FALSE for full path (e.g., PCI(..)/HD(..))
                                             //              TRUE for display only (e.g., Fs0:\path)
                                      FALSE  // AllowShortcuts: FALSE for canonical path
                                             //                 TRUE for simplified path (e.g., PciRoot(0x0)/Pci(0x1F,0x2)/Sata(0x0,0x0,0x0)/HD(1,GPT,...) -> Fs0:\)
                                    );

  if (DevicePathStr == NULL) {
    Print(L"ERROR: Failed to convert Device Path to text.\n");
    return EFI_OUT_OF_RESOURCES; // Or appropriate error
  }

  //
  // 5. Print the Device Path String
  //
  Print(L"\nDevice Path of current image: %s\n", DevicePathStr);

  //
  // 6. Clean up: Free the allocated string buffer
  //
  FreePool(DevicePathStr);

  return EFI_SUCCESS;
}


EFI_STATUS test_open_protocol(EFI_HANDLE ImageHandle)
{
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
  CHAR16                          FilePath[] = L"\\EFI\\BOOT\\FSBL.efi"; // Path relative to the root of the file system
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
    return Status;
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
    return Status;
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

    // You would need a more robust way to identify "FS1:".
    // In a real scenario, you'd match the device path, or assume a specific order.
    // For demonstration, let's just use the first one we find.
    // A better approach would involve parsing device paths to find the specific volume
    // that corresponds to FS1.
    // For simplicity, we'll assume the first SimpleFileSystem protocol is the one you want.
    // In a real scenario, you might need to convert the DevicePath to a human-readable string
    // to identify "FS1:". This is usually done with DevicePathToText protocol.
    // For now, let's just try the first found one and open its volume.

    // This is a simplification. To reliably identify "FS1:", you'd need to:
    // 1. Get the DevicePath of the handle: gBS->HandleProtocol(HandleBuffer[Index], &gEfiDevicePathProtocolGuid, (VOID**)&DevicePath);
    // 2. Convert DevicePath to text: gBS->LocateProtocol(&gEfiDevicePathToTextProtocolGuid, NULL, (VOID**)&DevicePathToText);
    //    DevicePathToText->ConvertDevicePathToText(DevicePath, FALSE, FALSE);
    // 3. Compare the resulting string (e.g., L"Fsi(" or similar representation for FS1)

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
    return EFI_NOT_FOUND;
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
    return Status;
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
    return Status;
  }

  Status = gBS->AllocatePool (EfiBootServicesData, BufferSize, (VOID **)&FileInfo);
  if (EFI_ERROR (Status)) {
    Print(L"Failed to allocate memory for file info: %r\n", Status);
    FileHandle->Close(FileHandle);
    Root->Close(Root);
    return Status;
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
    return Status;
  }

  UINT64 FileSize = FileInfo->FileSize;
  Print(L"File size of %s: %llu bytes\n", FilePath, FileSize);
  gBS->FreePool(FileInfo);

  // 5. Allocate buffer to read the file content
  Buffer = NULL;
  Status = gBS->AllocatePool (EfiBootServicesData, FileSize, &Buffer);
  if (EFI_ERROR (Status)) {
    Print(L"Failed to allocate memory for file content: %r\n", Status);
    FileHandle->Close(FileHandle);
    Root->Close(Root);
    return Status;
  }

  // 6. Read the file content
  BufferSize = (UINTN)FileSize; // BufferSize must be UINTN for Read()
  Status = FileHandle->Read (
                         FileHandle,
                         &BufferSize,
                         Buffer
                         );
  if (EFI_ERROR (Status)) {
    Print(L"Failed to read file: %r\n", Status);
    gBS->FreePool(Buffer);
    FileHandle->Close(FileHandle);
    Root->Close(Root);
    return Status;
  }

  Print(L"Successfully read %u bytes from %s.\n", (UINT32)BufferSize, FilePath);

  // Now 'Buffer' contains the content of X64.efi.
  // You can process this content (e.g., parse it as an EFI executable)

  // Example: print a few bytes (assuming it's a binary file)
  // Be careful printing raw binary data to the console, it might not be readable.
  // For demonstration, let's print the first 16 bytes in hex.
  Print(L"First 16 bytes of file:\n");
  for (UINTN i = 0; i < MIN(16, BufferSize); i++) {
    Print(L"%02x ", ((UINT8*)Buffer)[i]);
  }
  Print(L"\n");

  // 7. Close the file and volume handles
  FileHandle->Close(FileHandle);
  Root->Close(Root);
  gBS->FreePool(Buffer);

  return EFI_SUCCESS;
  

}

#ifdef SBC_BASEANSWER_TEST
SBCStatus  SBC_BaseAnswerValidate(UINT8 *answer, UINTN answerl);
SBCStatus SBC_GenDeviceID(UINT8 *devid);
#endif

#ifdef SBC_HASH_UNITEST_ENABLE
VOID SBC_HashMain(VOID);
#endif

#ifdef SBC_AES_UNITEST_ENABLE
VOID SBC_AES_TestMain(VOID);
VOID SBC_AesGcmTestMain(VOID);
#endif

#ifdef SBC_ECDSA_TEST_ENABLE
VOID SBC_EcDsa_TestMain(VOID);
#endif

#ifdef SBC_X509_TEST
SBCStatus  SBC_X509TestMain(VOID);
#endif
EFI_STATUS
EFIAPI
UefiMain (
  IN EFI_HANDLE        ImageHandle,
  IN EFI_SYSTEM_TABLE  *SystemTable
  )
{

//RETURN_STATUS status = RETURN_SUCCESS;
//
//_get_directory_and_file();
//status = SerialPortInitialize();
//if(status != RETURN_SUCCESS) {
//  dprint("SerialPortInitialize fail \n");
//  Print(L"SerialPortInitialize fail \n");
//}
//else {
//  dprint("SerialPortInitialize done \n");
//  Print(L"SerialPortInitialize done \n");
//}

//GetMotherboardSerialNumber();
// SBC_SSDGetSN();
// CpuidSerialNumber();
// GetMemorySerialNumbers();
  //enable_uart_serial();
//#ifdef SBC_HASH_UNITEST_ENABLE
//  SBC_HashMain();
//#endif
//#ifdef SBC_AES_UNITEST_ENABLE
//  SBC_AES_TestMain();
//  SBC_AesGcmTestMain();
//#endif
//
//#ifdef SBC_ECDSA_TEST_ENABLE
//  //ecc_test_func();
//  SBC_EcDsa_TestMain();
//
//#endif
//
#ifdef SBC_BASEANSWER_TEST
extern SBCStatus  SBC_FindBlkIoHandle(OUT VOID **hblk);

  VOID *blkio = NULL;
  SBC_FindBlkIoHandle(&blkio);
  Print(L"BlkIO Handle : %p \n", blkio);
  //nvme_get_serial();
//  CHAR8 *base_answer = "anti-tampering!?";
//    UINT8 devid[32] = {0,};
////  SBC_BaseAnswerValidate((UINT8 *)base_answer, strlen(base_answer));

//    SBC_GenDeviceID(devid);
  //get_blokio_handleparse();
    //st_open_protocol(ImageHandle);
    //st_deivce_paht_string(ImageHandle);
//  SBC_external_mem_print_bin("Device ID", devid, sizeof devid);
#endif
//
//#ifdef SBC_X509_TEST
//  SBC_X509TestMain();
//#endif
//
//  extern VOID SBC_FileCtrlTestMain(VOID);
//  SBC_FileCtrlTestMain();

    
   return EFI_SUCCESS;
}

