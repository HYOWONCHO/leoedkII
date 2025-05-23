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


//#include <openssl/sha.h>
//
#if 1
GLOBAL_REMOVE_IF_UNREFERENCED UINT8  Aes128CbcKey[] = {
  0xc2, 0x86, 0x69, 0x6d, 0x88, 0x7c, 0x9a, 0xa0, 0x61, 0x1b, 0xbb, 0x3e, 0x20, 0x25, 0xa4, 0x5a
};


GLOBAL_REMOVE_IF_UNREFERENCED UINT8  Aes128CbcIvec[] = {
  0x56, 0x2e, 0x17, 0x99, 0x6d, 0x09, 0x3d, 0x28, 0xdd, 0xb3, 0xba, 0x69, 0x5a, 0x2e, 0x6f, 0x58
};

GLOBAL_REMOVE_IF_UNREFERENCED UINT8  Aes256CbcKey[] = {
  0x10, 0x09, 0x3d, 0x28, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
  0x00, 0x00, 0x00, 0x00, 0x6d, 0x09, 0x3d, 0x28, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00
};

GLOBAL_REMOVE_IF_UNREFERENCED CONST UINT8  Aes128CbcData[] = {
  0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f,
  0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17, 0x18, 0x19, 0x1a, 0x1b, 0x1c, 0x1d, 0x1e, 0x1f
};








#endif

UINT32  gMaximumBasicFunction = CPUID_SIGNATURE;
VOID CpuidSerialNumber(VOID)
{
  CPUID_VERSION_INFO_EDX VersionInfoEdx;
  UINT32                  Ecx;
  UINT32                  Edx;


  Print(L"CPUID_SERIAL_NUMBER (Leaf %08x) \n", CPUID_SERIAL_NUMBER);

  if(CPUID_SERIAL_NUMBER > gMaximumBasicFunction) {
   return;
  }

  AsmCpuid( CPUID_VERSION_INFO, NULL, NULL, NULL, &VersionInfoEdx.Uint32 );
  if( VersionInfoEdx.Bits.PSN == 0 ) {
    Print(L" Not Supported \n");
    return;
  }

  AsmCpuid(CPUID_SERIAL_NUMBER, NULL, NULL, &Ecx, &Edx);

  Print (L"  EAX:%08x  EBX:%08x  ECX:%08x  EDX:%08x\n", 0, 0, Ecx, Edx);
  Print (L"  Processor Serial Number = %08x%08x%08x\n", 0, Edx, Ecx);

}


/**
 * 4 Byte random number convert to Byte type, It's put in the Byte Array
 *
 * @param UINT32
 * @param UINT8
 * @param UINT32 Length of OutBuf
 *
 * @return
 *
 */
EFI_STATUS
TrimDataUINT32ToUINT8(UINT32 *InBuf, UINT8 *OutBuf, UINT32 BufLen)
{
//UINT32 bufCnt = 0;
  int convert = 0;

  for(int x = 0; x < BufLen ; convert++) {

    OutBuf[x++] = (InBuf[convert] >> 24) & 0xFF;
    OutBuf[x++] = (InBuf[convert] >> 16) & 0xFF;
    OutBuf[x++] = (InBuf[convert] >> 8) & 0xFF;
    OutBuf[x++] = (InBuf[convert]);

  }

  return EFI_SUCCESS;


}










/**
 * @brif Obtain the Hash of message
 *
 * @param[IN,OUT]   handle    Handle of hash operation context ( but not in use )
 * @param[IN]       message   Buffer containing the message of hash
 * @param[IN]       msglen    Size of buffer in bytes
 * @param[OUT]      digest    Buffer where the hash is to be written
 *
 * @return On success, return the SBCOK, otherwise appropriate value
 */
SBCStatus SBC_HashSha256Compute(VOID **handle, UINT8* message, UINTN msglen, UINT8* digest)
{

  if(message == NULL || digest == NULL) {
    return SBCNULLP;
  }

  if(Sha256HashAll(message, msglen, digest) != TRUE) {
    return SBCFAIL;
  }


  return SBCOK;
}

/**
 * Computes the HMAC-SHA digest of a Message buffer 
 * 
 * @author leoc (4/28/25)
 * 
 * @param handle    Pointer to the HMAC handle context
 * @param mackey    Pointer to user-suppiled key
 * @param keysz     Key size in bytes
 * @param msg       Pointer to the buffer containing the digest
 *                  message
 * @param msglen    Message length in bytes
 * @param hmacvalue Pointer to a buffer that receive the
 *                  computed HMAC 
 * 
 * @return BOOLEAN 
 */
BOOLEAN SBC_hmac_compute(VOID *handle, UINT8 *mackey, UINTN keysz,
                          UINT8 *msg, UINTN msglen, UINT8 *hmacvalue)
{
  BOOLEAN ret = TRUE;

  ret = HmacSha256SetKey(handle, mackey, keysz);
  if(ret != TRUE) {
    Print(L"HMAC SetKey fail \n");
    return ret;
  }


  ret = HmacSha256Update(handle, msg, msglen);
  if(ret != TRUE) {
    Print(L"HMAC Update fail \n");
    return ret;
  }

  ret = HmacSha256Final(handle, hmacvalue);
  if(ret != TRUE) {
    Print(L"HMAC Update fail \n");
    return ret;
  }


  return ret;

}

UINTN SBC_GetFileSysHandleBuffer(EFI_HANDLE *handle)
{
  EFI_STATUS Status;
  EFI_HANDLE *h;
  UINTN hdlcnt;

   DEBUG((DEBUG_ERROR, "Buffer finding !!! \n"));
  // Confirm that the Protocol Available
  Status = gBS->LocateHandleBuffer(ByProtocol, 
                                   &gEfiSimpleFileSystemProtocolGuid,
                                   NULL,
                                   &hdlcnt,
                                   &h);
  if(EFI_ERROR(Status)) {
    Print(L"Protocol not found (%d) \n", Status);
    DEBUG((DEBUG_ERROR, "Protocol Not found \n"));
    return 0;
  }

  Print(L"Protocol found (count : %d, Handle Buffer : 0x%p) \n", 
        hdlcnt, *h);

  DEBUG((DEBUG_INFO, "Protocol found (count : %d, Handle Buffer : 0x%p) \n", 
        hdlcnt, *h));

  *handle = *h;
  return hdlcnt;

}

SBCStatus SBCWriteFile(EFI_HANDLE h_file, CHAR16* f_name, CHAR8 *f_data)
{
  EFI_STATUS Status;
  EFI_SIMPLE_FILE_SYSTEM_PROTOCOL *FileSystem;
  EFI_FILE_PROTOCOL *RootDir, *File;
  UINTN DataSize = AsciiStrLen(f_data);

  DEBUG((DEBUG_INFO, "Handle : %s, %d", f_name,DataSize));

  Status = gBS->HandleProtocol(h_file,
                               &gEfiSimpleFileSystemProtocolGuid,
                               (VOID **)&FileSystem);
  if(EFI_ERROR(Status)) {
    DEBUG((DEBUG_ERROR, "%a:%d HandleProtocol Fail \n", 
           (CHAR8 *)__FUNCTION__, __LINE__));
    return SBCPROTO;
  }

    // Open the roor directory
  Status = FileSystem->OpenVolume(FileSystem, &RootDir);
  if (EFI_ERROR(Status)) {
        DEBUG((DEBUG_INFO, " %a:%d OpenVolume File Systam fail (%d) \r\n", 
           __FUNCTION__, __LINE__, Status));
    return SBCFAIL;
  }

  Status = RootDir->Open(RootDir, &File, f_name,
                          EFI_FILE_MODE_READ |EFI_FILE_MODE_CREATE | EFI_FILE_MODE_WRITE, 
                         0 );
  if(EFI_ERROR(Status)) {
      DEBUG((DEBUG_INFO, " %a:%d RootDir->Open fail (%d) \r\n", 
                                      __FUNCTION__, __LINE__, Status));
      return SBCIO;
  }

  Status = File->Write(File, &DataSize, f_data);
  if(EFI_ERROR(Status)) {
      DEBUG((DEBUG_INFO, " %a:%d File->Write fail (%d) \r\n", 
                                      __FUNCTION__, __LINE__, Status));
      return SBCIO;
  }

  File->Flush(File);
  File->Close(File);


  return SBCOK;

}

SBCStatus SBCCreateFile(EFI_HANDLE h_file, CHAR16* f_name)
{
  EFI_STATUS Status;
  EFI_SIMPLE_FILE_SYSTEM_PROTOCOL *FileSystem;
  EFI_FILE_PROTOCOL *RootDir, *File;

  Status = gBS->HandleProtocol(h_file,
                               &gEfiSimpleFileSystemProtocolGuid,
                               (VOID **)&FileSystem);
  if(EFI_ERROR(Status)) {
    DEBUG((DEBUG_ERROR, "%a:%d HandleProtocol Fail \n", 
           (CHAR8 *)__FUNCTION__, __LINE__));
    return SBCPROTO;
  }

    // Open the roor directory
  Status = FileSystem->OpenVolume(FileSystem, &RootDir);
  if (EFI_ERROR(Status)) {
        DEBUG((DEBUG_INFO, " %a:%d OpenVolume File Systam fail (%d) \r\n", 
           __FUNCTION__, __LINE__, Status));
    return SBCFAIL;
  }

  Status = RootDir->Open(RootDir, &File, f_name,EFI_FILE_MODE_CREATE, 0 );
  if(EFI_ERROR(Status)) {
      DEBUG((DEBUG_INFO, " %a:%d RootDir->Open fail (%d) \r\n", 
                          (CHAR8 *)__FUNCTION__, __LINE__, Status));
  }

  return SBCOK;

}

EFI_STATUS SBC_ReadFlie(EFI_HANDLE ImageHandle, CHAR16 *FileNames)
{
  EFI_STATUS Status;
  EFI_SIMPLE_FILE_SYSTEM_PROTOCOL *FileSystem;
  EFI_FILE_PROTOCOL *RootDir, *File;
  UINTN BufferSize = 128;
  CHAR8 Buffer[128];

  DEBUG((DEBUG_INFO,"Image Handle : %p \r\n", ImageHandle));
  DEBUG((DEBUG_INFO,"Read File : %s \r\n", (CHAR8 *)FileNames));

  // Locate file system
  Status = gBS->HandleProtocol(ImageHandle, 
                               &gEfiSimpleFileSystemProtocolGuid,
                               (VOID **)&FileSystem);
  if(EFI_ERROR(Status)) {
    DEBUG((DEBUG_INFO, " %a:%d Locate File Systam fail (%d) \r\n", 
           __FUNCTION__, __LINE__, Status));
    return Status;
  }

  // Open the roor directory
  Status = FileSystem->OpenVolume(FileSystem, &RootDir);
  if (EFI_ERROR(Status)) {
        DEBUG((DEBUG_INFO, " %a:%d OpenVolume File Systam fail (%d) \r\n", 
           __FUNCTION__, __LINE__, Status));
    return Status;
  }

  // Open the file
  Status = RootDir->Open(RootDir, &File, FileNames, EFI_FILE_MODE_READ, 0);
  if (EFI_ERROR(Status)) {
      DEBUG((DEBUG_INFO, " %a:%d RootDir->Open fail (%d) \r\n", 
     __FUNCTION__, __LINE__, Status));
    return Status;
  }

  // Read the file
  Status = File->Read(File, &BufferSize, Buffer);
  if (EFI_ERROR(Status)) {
      DEBUG((DEBUG_INFO, " %a:%d File->Read fail (%d) \r\n", 
              __FUNCTION__, __LINE__, Status));
      Print(L"File Content: %a\n", Buffer);
  }

  SBC_mem_print_bin(NULL, (UINT8 *)Buffer, (UINTN)BufferSize);

  // Close the file
  File->Close(File);

  return Status;


}

EFI_STATUS SBC_ListDirectory(EFI_HANDLE ImageHandle __attribute__((unused))) {
    EFI_STATUS Status;
    EFI_SIMPLE_FILE_SYSTEM_PROTOCOL *FileSystem;
    EFI_FILE_PROTOCOL *RootDir, *File;
    EFI_FILE_INFO *FileInfo;
    UINTN BufferSize = 256;

    Status = gBS->LocateProtocol(&gEfiSimpleFileSystemProtocolGuid, 
                                 NULL,
                                 (VOID**)&FileSystem);
    if (EFI_ERROR(Status)) {
       DEBUG((DEBUG_INFO, "HandleProtoocl Not found (%d) \r\n", Status));
       return Status;
    }

    Status = FileSystem->OpenVolume(FileSystem, &RootDir);
    if (EFI_ERROR(Status)) {
       DEBUG((DEBUG_INFO, "OpenVolume fail (%d) \r\n", Status));
      return Status;
    }

    Status = RootDir->Open(RootDir, &File, L"\\EmulatorPkg", EFI_FILE_MODE_READ, EFI_FILE_DIRECTORY);
    if (EFI_ERROR(Status))
    {
      DEBUG((DEBUG_INFO, "RootDir fail (%d) \r\n", Status));
      return Status;
    }

    BufferSize = sizeof(EFI_FILE_INFO) + 1024;
    FileInfo = AllocatePool(BufferSize);
    while (File->Read(File, &BufferSize, FileInfo) == EFI_SUCCESS) {
        Print(L"File: %s\n", FileInfo->FileName);
    }

    FreePool(FileInfo);
    File->Close(File);

    return Status;
}


EFI_STATUS
EFIAPI
WriteToFile (
  IN EFI_HANDLE        ImageHandle
) {
    EFI_FILE_PROTOCOL *Root;
    EFI_FILE_PROTOCOL *File;
    EFI_SIMPLE_FILE_SYSTEM_PROTOCOL *FileSystem;
    EFI_STATUS Status;
    CHAR16 FileName[] = L"test.txt";
    CHAR8 Data[] = "Hello, UEFI!";
    UINTN DataSize = sizeof(Data);
#if 0
    // Locate the file system
    Status = SystemTable->BootServices->LocateProtocol(
        &gEfiSimpleFileSystemProtocolGuid, NULL, (VOID **)&FileSystem);
    if (EFI_ERROR(Status)) {
        return Status;
    }
#endif


    Status = gBS->HandleProtocol(ImageHandle, 
                                 &gEfiSimpleFileSystemProtocolGuid, 
                                 (VOID**)&FileSystem);
    if (EFI_ERROR(Status)) {
       DEBUG((DEBUG_INFO, "HandleProtoocl Not found (%d) \r\n", Status));
       return Status;
    }

    // Open the root volume
    Status = FileSystem->OpenVolume(FileSystem, &Root);
    if (EFI_ERROR(Status)) {
      DEBUG((DEBUG_INFO, "OpenVolume (%d) \r\n", Status));
        return Status;
    }

    // Open (or create) the file with read/write access
    Status = Root->Open(Root, &File, FileName,
                        EFI_FILE_MODE_READ | EFI_FILE_MODE_WRITE | EFI_FILE_MODE_CREATE,
                        0);
    if (EFI_ERROR(Status)) {
        DEBUG((DEBUG_INFO, "Open (%d) \r\n", Status));
        return Status;
    }

    // Write data to the file
    Status = File->Write(File, &DataSize, Data);
    if (EFI_ERROR(Status)) {
        DEBUG((DEBUG_INFO, "Write (%d) \r\n", Status));
        return Status;
    }

    // Close the file
    File->Close(File);

    return EFI_SUCCESS;
}

// Hypothetical vendor-specific SMBIOS record for an SSD.
// (Replace 0xC0 with the proper type value and define the fields as per your platform.)
#pragma pack(1)
typedef struct {
  EFI_SMBIOS_TABLE_HEADER Hdr;
  UINT8               Reserved;
  // ... Other fields specific to the record
  UINT8               SerialNumberStrIndex; // Index into the strings section
  // ... Possibly more fields ...
} SMBIOS_VENDOR_STORAGE;
#pragma pack()

//
// Helper function to get a string from an SMBIOS record.
// The strings follow immediately after the formatted portion of the record.
// They are ASCII, null-terminated, and the block ends with a double-NULL.
//
CHAR8 *
GetSmbiosString (
  IN EFI_SMBIOS_TABLE_HEADER *Record,
  IN UINT8              StringNumber
  )
{
  UINTN   Index;
  CHAR8   *StringPtr;

  if (StringNumber == 0) {
    return NULL;
  }

  // Point to the first string following the fixed structure.
  StringPtr = (CHAR8 *)(Record + 1);

  //
  // Loop until we reach the designated string.
  //
  for (Index = 1; Index < StringNumber; Index++) {
    // Skip the current string.
    while (*StringPtr != 0) {
      StringPtr++;
    }
    // Skip the null terminator.
    StringPtr++;
    // If we've reached the end (double-NULL), return NULL.
    if (*StringPtr == 0) {
      return NULL;
    }
  }

  return StringPtr;
}

EFI_STATUS GetSSDSerial(VOID)
{
    EFI_STATUS            Status;
  EFI_SMBIOS_PROTOCOL   *Smbios;
  EFI_SMBIOS_TABLE_HEADER   *Record;
  EFI_SMBIOS_HANDLE     SmbiosHandle = SMBIOS_HANDLE_PI_RESERVED;
  CHAR8                 *SerialString;

  // Locate the SMBIOS protocol.
  Status = gBS->LocateProtocol(&gEfiSmbiosProtocolGuid, NULL, (VOID **)&Smbios);
  if (EFI_ERROR(Status)) {
    Print(L"Error locating SMBIOS protocol: %r\n", Status);
    return Status;
  }

  // Iterate through all SMBIOS records.
  while ((Status = Smbios->GetNext(Smbios, &SmbiosHandle, NULL, &Record, NULL)) == EFI_SUCCESS) {
    //
    // Check if this record is our assumed vendor-specific SSD record.
    // In this example, we check for record type 0xC0.
    // Adjust this value as needed.
    //

    Print(L"Record->Type : 0x%02x\n", Record->Type);
    if (Record->Type == 0xC0) {
      SMBIOS_VENDOR_STORAGE *StorageRecord = (SMBIOS_VENDOR_STORAGE *)Record;
      
      // Get the serial number string using the string index.
      SerialString = GetSmbiosString(Record, StorageRecord->SerialNumberStrIndex);
      if (SerialString != NULL) {
        Print(L"SSD Serial Number: %a\n", SerialString);
      } else {
        Print(L"SSD serial number string not found.\n");
      }
    }
  }

  return Status;
}

EFI_STATUS GetDiskSerialNumber(VOID) 
{
    EFI_STATUS Status;
    EFI_HANDLE *HandleBuffer;
    UINTN HandleCount;
    EFI_BLOCK_IO_PROTOCOL *BlockIo;
    
    // Locate handles supporting Block IO Protocol
    Status = gBS->LocateHandleBuffer(ByProtocol, &gEfiBlockIoProtocolGuid, NULL, &HandleCount, &HandleBuffer);
    if (EFI_ERROR(Status)) {
          DEBUG((DEBUG_ERROR, "[%a:%d] LocateHandleBuffer :%d \n",__FUNCTION__,__LINE__, Status));
        return Status;
    }

    // Loop through all block devices
    for (UINTN i = 0; i < HandleCount; i++) {
        Status = gBS->HandleProtocol(HandleBuffer[i], &gEfiBlockIoProtocolGuid, (VOID **)&BlockIo);
        if (EFI_ERROR(Status)) {
          DEBUG((DEBUG_ERROR, "[%a:%d] HandleProtocol :%d \n",__FUNCTION__,__LINE__, Status));
            continue;
        }

        if (BlockIo->Media->RemovableMedia) {
            Print(L"Skipping removable media...\n");
            continue;
        }

        // At this point, the BlockIo interface allows interaction with the disk
        // The Serial Number is typically retrieved through a pass-through ATA command
        Print(L"Disk detected, but retrieving serial requires ATA pass-through.\n");
    }

    return EFI_SUCCESS;
}

EFI_STATUS SBC_SSDGetSN(VOID)
{
  EFI_BLOCK_IO_PROTOCOL *BlockIo;
  EFI_HANDLE *Handles;
  UINTN HandleCount;
  UINTN Index;
  EFI_DISK_INFO_PROTOCOL *DiskInfo;
  UINT8 IdentifyData[512]; // Buffer for device info
  UINTN BufferSize = sizeof(IdentifyData);
  EFI_STATUS Status;

  DEBUG((DEBUG_INFO, "[%a:%d] Locate Block I/O Protocol for the SSD) \n",
           __FUNCTION__,__LINE__));
#if 1
  // Locate Block I/O Protocol for the SSD
  Status = gBS->LocateHandleBuffer(ByProtocol, &gEfiSimpleFileSystemProtocolGuid, 
                                   NULL, &HandleCount, &Handles);
  if (EFI_ERROR(Status)) {
    DEBUG((DEBUG_ERROR, "[%a:%d] LocateHandleBuffer  \n",
           __FUNCTION__,__LINE__));
    return Status;
  }

  DEBUG((DEBUG_ERROR, "[%a:%d] Handle Count  (%d) \n",
           __FUNCTION__,__LINE__, HandleCount));


  for( Index = 0; Index < HandleCount; Index++ ) {
    Status = gBS->HandleProtocol(
                              Handles[Index],
                              &gEfiBlockIoProtocolGuid,
                              (VOID **)&BlockIo
                              );
    if(!EFI_ERROR(Status)) {
      Print(L"gEfiBlockIoProtocolGuid HandleProtocol fail \n");
      continue;
    }

    DEBUG((DEBUG_INFO, "[%a:%d] Buffre Size : %d \n", __FUNCTION__,__LINE__, Index));
  // Retrieve Disk Info Protocol
    Status = gBS->HandleProtocol(Handles[Index], &gEfiDiskInfoProtocolGuid, (VOID **)&DiskInfo);
    if (EFI_ERROR(Status)) {
      DEBUG((DEBUG_ERROR, "[%a:%d] HandleProtocol (0x%p) \n",
             __FUNCTION__,__LINE__, DiskInfo));
      Print(L"gEfiDiskInfoProtocolGuid HandleProtocol fail \n");
      return Status;
    }

    Status = DiskInfo->Identify(DiskInfo, (VOID *)IdentifyData, (UINT32 *)&BufferSize);
    if (EFI_ERROR(Status)) {
      DEBUG((DEBUG_ERROR, "[%a:%d] Identify (0x%p) \n",
             __FUNCTION__,__LINE__));
      return Status;

    }

    // Extract Serial Number (Example for SATA)
    CHAR16 SerialNumber[21];
    CopyMem(SerialNumber, &IdentifyData[20], 20); // Serial is stored at offset 20 in IDENTIFY DEVICE
    SerialNumber[20] = L'\0'; // Null-terminate

    Print(L"SSD Serial Number: %s\n", SerialNumber);
    SBC_mem_print_bin("Memory Serial Number", (UINT8 *)SerialNumber, 20);

  }

#endif
//DEBUG((DEBUG_INFO, "[%a:%d]\n", __FUNCTION__,__LINE__));
//Status = gBS->LocateProtocol(&gEfiDiskInfoProtocolGuid,
//                           NULL,
//                           (VOID**)&DiskInfo);
//if (EFI_ERROR(Status)) {
  DEBUG((DEBUG_ERROR, "[%a:%d] LocateProtocol (0x%p) \n",
         __FUNCTION__,__LINE__, DiskInfo));
//  return Status;
//}
//DEBUG((DEBUG_INFO, "[%a:%d]\n", __FUNCTION__,__LINE__));
//DEBUG((DEBUG_INFO, "[%a:%d] ( Disk Info 0x%p 0x%p) \n",
//                    __FUNCTION__,__LINE__,DiskInfo, *DiskInfo));
//// Query the IDENTIFY DEVICE data
//Status = DiskInfo->Identify(DiskInfo, (VOID *)IdentifyData, (UINT32 *)&BufferSize);
//if (EFI_ERROR(Status)) {
  DEBUG((DEBUG_ERROR, "[%a:%d] Identify (0x%p) \n",
         __FUNCTION__,__LINE__));
//  return Status;
//
//}
//
//// Extract Serial Number (Example for SATA)
//CHAR16 SerialNumber[21];
//CopyMem(SerialNumber, &IdentifyData[20], 20); // Serial is stored at offset 20 in IDENTIFY DEVICE
//SerialNumber[20] = L'\0'; // Null-terminate
//
//Print(L"SSD Serial Number: %s\n", SerialNumber);

  return EFI_SUCCESS;

}

EFI_STATUS GetMemorySerialNumbers() {
    EFI_SMBIOS_PROTOCOL *Smbios;
    EFI_STATUS Status;
    EFI_SMBIOS_HANDLE SmbiosHandle = SMBIOS_HANDLE_PI_RESERVED;
    SMBIOS_TABLE_TYPE17 *Type17Record;
    EFI_SMBIOS_TABLE_HEADER *Record;

    UINT8 snbuf[512] = {0 ,};
    int sncnt = 0;

    DEBUG((DEBUG_INFO, "[%a:%d] \n",__FUNCTION__,__LINE__));
    Status = gBS->LocateProtocol(&gEfiSmbiosProtocolGuid, NULL, (VOID **)&Smbios);
    if (EFI_ERROR(Status)) {
        //DEBUG((DEBUG_ERROR , "%a:%d LocateProtocol fail (%d) \n",__func__, __LINE__, Status));

        return Status;
    }

    while (!EFI_ERROR((Status = Smbios->GetNext(Smbios, &SmbiosHandle, NULL, &Record, NULL)))) {
        //DEBUG((DEBUG_INFO, "[%a:%d] (GetNext : %d) (Record->Type : %d) \n",__FUNCTION__,__LINE__, Status,Record->Type));
        if (Record->Type == SMBIOS_TYPE_MEMORY_DEVICE) {
            Type17Record = (SMBIOS_TABLE_TYPE17 *)Record;
            

            // Extract Serial Number (this is an index into the string table)
            UINT8 SerialNumberIndex = Type17Record->SerialNumber;
            CHAR8 *SerialNumberString = (CHAR8 *)(Record + Record->Length);
            DEBUG((DEBUG_INFO, "[%a:%d] SerialNumberIndex : %d \n", __FUNCTION__,__LINE__,SerialNumberIndex));
            if (SerialNumberIndex > 0) {
                // Move to the correct string entry in the table
                for (UINT8 i = 1; i < SerialNumberIndex; i++) {
                    sncnt = 0;
                    while (*SerialNumberString != '\0') {
                        snbuf[sncnt++] = *SerialNumberString;
                        SerialNumberString++;
                    }
                    SerialNumberString++;
                }
                
                // Print the Serial Number
                //Print(L"Memory Serial Number: %a\n", SerialNumberString);
                SBC_mem_print_bin("Memory Serial Number", (UINT8 *)snbuf, sncnt);
            }
        }
    }

    return EFI_SUCCESS;
}


#include <Protocol/LoadedImage.h>

EFI_STATUS ListInstalledProtocols() 
{
    EFI_STATUS Status;
    UINTN HandleCount;
    EFI_HANDLE *HandleBuffer;
    
    Status = gBS->LocateHandleBuffer(ByProtocol, NULL, NULL, &HandleCount, &HandleBuffer);
    if (EFI_ERROR(Status)) {
        DEBUG((DEBUG_ERROR, "[%a:%d] (LocateHandleBuffer Fal : %d) \n",__FUNCTION__,__LINE__, Status));
        Print(L"ListInstalledProtocols LocateProtocol fail \n");
        return Status;
    }
    
    Print(L"Installed Protocols: %d\n", HandleCount);
    return EFI_SUCCESS;
}

EFI_STATUS GetMotherboardSerialNumber() 
{
    EFI_SMBIOS_PROTOCOL *Smbios;
    EFI_STATUS Status;
    EFI_SMBIOS_HANDLE SmbiosHandle = SMBIOS_HANDLE_PI_RESERVED;
    SMBIOS_TABLE_TYPE2 *Type2Record;
    EFI_SMBIOS_TABLE_HEADER *Record;

    Status = gBS->LocateProtocol(&gEfiSmbiosProtocolGuid, NULL, (VOID **)&Smbios);
    if (EFI_ERROR(Status)) {
        Print(L"Motherboard Serial Number LocateProtocol fail \n");
        DEBUG((DEBUG_ERROR, "[%a:%d] (LocateProtocol : %d) \n",__FUNCTION__,__LINE__, Status));
        return Status;
    }

    while (!EFI_ERROR((Status = Smbios->GetNext(Smbios, &SmbiosHandle, NULL, &Record, NULL)))) {
        //DEBUG((DEBUG_INFO, "[%a:%d] (GetNext : %d) (Record->Type : %d) \n",__FUNCTION__,__LINE__, Status,Record->Type));
        if (Record->Type == SMBIOS_TYPE_BASEBOARD_INFORMATION) {
            Type2Record = (SMBIOS_TABLE_TYPE2 *)Record;

            // Extract Serial Number (this is an index into the string table)
            UINT8 SerialNumberIndex = Type2Record->SerialNumber;
            CHAR8 *SerialNumberString = (CHAR8 *)(Record + Record->Length);
            DEBUG((DEBUG_INFO, "[%a:%d] SerialNumberIndex : %d \n", __FUNCTION__,__LINE__,SerialNumberIndex));
            if (SerialNumberIndex > 0) {
                //Print(L"Motherboard Serial Number: %a\n", SerialNumberString);
                //SBC_mem_print_bin("Before SN", (UINT8 *)SerialNumberString, 64);
                // Move to the correct string entry in the table
                for (UINT8 i = 1; i < SerialNumberIndex; i++) {
                    while (*SerialNumberString != '\0') {
                        SerialNumberString++;
                    }
                    SerialNumberString++;
                }

                // Print the Serial Number
                Print(L"Motherboard Serial Number: %a\n", SerialNumberString);
                SBC_mem_print_bin("SN", (UINT8 *)SerialNumberString, strlen(SerialNumberString));
            }
        }
    }

    DEBUG((DEBUG_INFO, "[%a:%d]  \n",__FUNCTION__,__LINE__));

    return EFI_SUCCESS;
}



//int ecdh_test_func(UINT8 *alice_q, UINT8 *alice_xy, UINT8 *bob_q, UINT8 *bob_xy)
int ecdh_test_func()
{
  int ret = -1;


  unsigned char alice_q[32] = {
  	0xC8, 0x8F, 0x01, 0xF5, 0x10, 0xD9, 0xAC, 0x3F, 0x70, 0xA2, 0x92, 0xDA,
  	0xA2, 0x31, 0x6D, 0xE5, 0x44, 0xE9, 0xAA, 0xB8, 0xAF, 0xE8, 0x40, 0x49,
  	0xC6, 0x2A, 0x9C, 0x57, 0x86, 0x2D, 0x14, 0x33
  };

  unsigned char alice_xy[64] = {
  	0xDA, 0xD0, 0xB6, 0x53, 0x94, 0x22, 0x1C, 0xF9, 0xB0, 0x51, 0xE1, 0xFE,
  	0xCA, 0x57, 0x87, 0xD0, 0x98, 0xDF, 0xE6, 0x37, 0xFC, 0x90, 0xB9, 0xEF,
  	0x94, 0x5D, 0x0C, 0x37, 0x72, 0x58, 0x11, 0x80, 0x52, 0x71, 0xA0, 0x46,
  	0x1C, 0xDB, 0x82, 0x52, 0xD6, 0x1F, 0x1C, 0x45, 0x6F, 0xA3, 0xE5, 0x9A,
  	0xB1, 0xF4, 0x5B, 0x33, 0xAC, 0xCF, 0x5F, 0x58, 0x38, 0x9E, 0x05, 0x77,
  	0xB8, 0x99, 0x0B, 0xB3
  };

  unsigned char bob_q[32] = {
  	0xC6, 0xEF, 0x9C, 0x5D, 0x78, 0xAE, 0x01, 0x2A, 0x01, 0x11, 0x64, 0xAC,
  	0xB3, 0x97, 0xCE, 0x20, 0x88, 0x68, 0x5D, 0x8F, 0x06, 0xBF, 0x9B, 0xE0,
  	0xB2, 0x83, 0xAB, 0x46, 0x47, 0x6B, 0xEE, 0x53
  };

  unsigned char bob_xy[64] = {
  	0xD1, 0x2D, 0xFB, 0x52, 0x89, 0xC8, 0xD4, 0xF8, 0x12, 0x08, 0xB7, 0x02,
  	0x70, 0x39, 0x8C, 0x34, 0x22, 0x96, 0x97, 0x0A, 0x0B, 0xCC, 0xB7, 0x4C,
  	0x73, 0x6F, 0xC7, 0x55, 0x44, 0x94, 0xBF, 0x63, 0x56, 0xFB, 0xF3, 0xCA,
  	0x36, 0x6C, 0xC2, 0x3E, 0x81, 0x57, 0x85, 0x4C, 0x13, 0xC5, 0x8D, 0x6A,
  	0xAC, 0x23, 0xF0, 0x46, 0xAD, 0xA3, 0x0F, 0x83, 0x53, 0xE7, 0x4F, 0x33,
  	0x03, 0x98, 0x72, 0xAB
  };

  unsigned char expected_answer[32] = {
    0xD6, 0x84, 0x0F, 0x6B, 0x42, 0xF6, 0xED, 0xAF, 0xD1, 0x31, 0x16, 0xE0,
    0xE1, 0x25, 0x65, 0x20, 0x2F, 0xEF, 0x8E, 0x9E, 0xCE, 0x7D, 0xCE, 0x03,
    0x81, 0x24, 0x64, 0xD0, 0x4B, 0x94, 0x42, 0xDE
  };

  SBCEccCtx *alice;
  SBCEccCtx *bob;

  UINT8 bobkey[256] ={0, };
  UINT8 alicekey[256] = {0, };
  



  alice = AllocatePool(sizeof *alice);
  if(alice == NULL) {
    DEBUG((DEBUG_ERROR, "%s:%d ECC test allocate fail \n", __FUNCTION__,__LINE__));
    ret = SBCNULLP;
    goto errdone;
  }

  bob = AllocatePool(sizeof *bob);
  if(alice == NULL) {
    DEBUG((DEBUG_ERROR, "%s:%d ECC test allocate fail \n", __FUNCTION__,__LINE__));
    ret = SBCNULLP;
    goto errdone;
  }

  ZeroMem(alice, sizeof(SBCEccCtx));
  ZeroMem(bob, sizeof(SBCEccCtx));
  alice->curveid = CRYPTO_NID_SECP256R1;
  alice->sharedkey.value = alicekey;

  dprint("--- Alice Testing ---");
  if(SBC_GenShareSeucrityKey(alice,
                             alice_q, 32,
                             bob_xy, 64) != SBCOK) {
    eprint("Alice get shared scret key fail");
    goto errdone;

  }

  bob->curveid = CRYPTO_NID_SECP256R1;
  bob->sharedkey.value = bobkey;
  dprint("--- Bob Testing ---");
  if(SBC_GenShareSeucrityKey(bob,
                             bob_q, 32,
                             alice_xy, 64) != SBCOK) {
    eprint("Bob get shared scret key fail");
    goto errdone;

  }

  SBC_external_mem_print_bin("Alice secret key", alice->sharedkey.value, alice->sharedkey.length);
  SBC_external_mem_print_bin("Bob secret key", bob->sharedkey.value, bob->sharedkey.length);

  SBC_external_mem_print_bin("Expected Answer", expected_answer, bob->sharedkey.length);

  if(CompareMem(expected_answer, alice->sharedkey.value, sizeof expected_answer) != 0) {
    eprint("Compare fail value %a != %a for length %d bytes", 
           expected_answer,
           alice->sharedkey.value,
           sizeof expected_answer
           );
  }
  else {
    Print(L"Alice DH answer passed \n");
  }

  if(CompareMem(expected_answer, bob->sharedkey.value, sizeof expected_answer) != 0) {
    eprint("Compare fail value %a != %a for length %d bytes", 
           expected_answer,
           alice->sharedkey.value,
           sizeof expected_answer
           );
  }
  else {
    Print(L"Bob DH answer passed \n");
  }

  ret = 0;


errdone:

  if(alice != NULL) {
    FreePool(alice);
  }

  if(bob != NULL) {
    FreePool(bob);
  }

  return ret;



}

int ecc_test_func(VOID)
{
  SBCEccCtx *alice;
  SBCEccCtx *bob;

//SBCEccCtx xalice;
//SBCEccCtx xbob;
  UINT8 pubkey[256];
  UINT8 privkey[256];
  UINT8 bobpriv[256];
  UINT8 bobpub[256];

  UINT8 bobkey[256];
  UINT8 alicekey[256];

//LV_t lvpub;
//LV_t lvpriv;
  UINTN keybit = 256;

  SBCStatus ret = SBCOK;

  alice = AllocatePool(sizeof *alice);
  if(alice == NULL) {
    DEBUG((DEBUG_ERROR, "%a:%d ECC test allocate fail \n", __FUNCTION__,__LINE__));
    ret = SBCNULLP;
    goto errdone;
  }

  alice->pubkey.value = (VOID *)pubkey;
  alice->privkey.value = (VOID *)privkey;
  alice->privkey.length = keybit >> 3;
  alice->pubkey.length = 64;//alice->privkey.length * 2;
  alice->sharedkey.value = (VOID *)alicekey;
  alice->sharedkey.length = 0;

  ret = SBC_EccKeyGen(alice, CRYPTO_NID_SECP256R1);
  if(ret != SBCOK) {
    DEBUG((DEBUG_ERROR, "%a:%d ECC key gen fail \n", __FUNCTION__,__LINE__));
    ret = SBCFAIL;
    goto errdone;
  }

  SBC_mem_print_bin("alice Private Key", alice->privkey.value, alice->privkey.length);
  SBC_mem_print_bin("alice Pub Key", alice->pubkey.value, alice->pubkey.length);

  bob = AllocatePool(sizeof *bob);
  if(bob == NULL) {
    DEBUG((DEBUG_ERROR, "%a:%d ECC test allocate fail \n", __FUNCTION__,__LINE__));
    ret = SBCNULLP;
    goto errdone;
  }

  bob->pubkey.value = (VOID *)bobpub;
  bob->privkey.value = (VOID *)bobpriv;
  bob->privkey.length = keybit >> 3;
  bob->pubkey.length = 64; //bob->privkey.length * 2;
  bob->sharedkey.value = (VOID *)bobkey;
  bob->sharedkey.length = 0;

  //alice->curveid = CRYPTO_NID_SECP256R1;
  ret = SBC_EccKeyGen(bob, CRYPTO_NID_SECP256R1);
  if(ret != SBCOK) {
    DEBUG((DEBUG_ERROR, "%a:%d ECC key gen fail \n", __FUNCTION__,__LINE__));
    ret = SBCFAIL;
    goto errdone;
  }

  SBC_mem_print_bin("Bob Private Key", bob->privkey.value, bob->privkey.length);
  SBC_mem_print_bin("Bob Pub Key", bob->pubkey.value, bob->pubkey.length);

  //ecdh_test_func(alice->privkey.value, alice->pubkey.value,
  //               bob->privkey.value, bob->pubkey.value);
  ecdh_test_func();

errdone:

  if(alice != NULL) {
    FreePool(alice);
  }

  if(bob != NULL) {
    FreePool(bob);
  }

  return ret;
}

VOID enable_uart_serial(VOID)
{
#if 0
  EFI_HANDLE ControllerHandle;
  EFI_STATUS Status;
  UINTN hndlcnt;

  DEBUGPORT_DEVICE  mDebugPortDevice = {
    DEBUGPORT_DEVICE_SIGNATURE,
    (EFI_HANDLE)0,
    (EFI_HANDLE)0,
    (EFI_DEVICE_PATH_PROTOCOL *)NULL,
    {
      DebugPortReset,
      DebugPortWrite,
      DebugPortRead,
      DebugPortPoll
    },
    (EFI_HANDLE)0,
    (EFI_SERIAL_IO_PROTOCOL *)NULL,
    DEBUGPORT_UART_DEFAULT_BAUDRATE,
    DEBUGPORT_UART_DEFAULT_FIFO_DEPTH,
    DEBUGPORT_UART_DEFAULT_TIMEOUT,
    (EFI_PARITY_TYPE)DEBUGPORT_UART_DEFAULT_PARITY,
    DEBUGPORT_UART_DEFAULT_DATA_BITS,
    (EFI_STOP_BITS_TYPE)DEBUGPORT_UART_DEFAULT_STOP_BITS
  };
  Status = gBS->LocateHandleBuffer(
                                     ByProtocol,
                                     &gEfiSerialIoProtocolGuid,
                                     NULL,
                                     &hndlcnt,
                                     (VOID **)&ControllerHandle
                                      
      );

  if (EFI_ERROR(Status)) {
      Print(L"LocateHandleBuffer not found!\n");
      DEBUG((DEBUG_ERROR, "SerialIo Protocol not found!\n"));
      return;
  } else {
      Print(L"LocateHandleBuffer enabled.\n");
      DEBUG((DEBUG_INFO, "SerialIo Protocol enabled.\n"));
  }


  Status = gBS->OpenProtocol(
                  ControllerHandle,
                  &gEfiSerialIoPrhotocolGuid,
                  (VOID **)&mDebugPortDevice.SerialIoBinding,

      );
  SerialIo->SetAttributes(
          SerialIo,
          115200,  // Baud Rate
          0,       // Receive FIFO Depth
          0,       // Timeout
          NoParity,       // Parity
          8,        // Data
          OneStopBit        // Stop Bits
      );

  CHAR8 Buffer[] = "Hello, UART!";
  UINTN BufferSize = sizeof(Buffer);
  SerialIo->Write(SerialIo, &BufferSize, Buffer);
#endif

    EFI_STATUS Status;
    EFI_SERIAL_IO_PROTOCOL *SerialIo;

    // 1. Locate the Serial IO Protocol
    Status = gBS->LocateProtocol(&gEfiSerialIoProtocolGuid, NULL, (VOID **)&SerialIo);
    if (EFI_ERROR(Status)) {
        Print(L"Error: Unable to locate Serial Io Protocol: %r\n", Status);
        return ;
    }
    Print(L"Serial Io Protocol located successfully.\n");

    // 2. Configure the UART settings
    //    - Baud Rate: 115200
    //    - Receive FIFO Depth: 0 (use hardware default)
    //    - Timeout: 0  (zero indicates that no timeout is applied)
    //    - Parity: DefaultParity (commonly EfiParityNone in many implementations)
    //    - Data Bits: 8
    //    - Stop Bits: DefaultStopBits (commonly one stop bit)
    Status = SerialIo->SetAttributes(
                   SerialIo,
                   115200,           // BaudRate
                   0,                // Receive FIFO Depth (0 uses default)
                   0,                // Timeout (in 1/10 ms, 0 means no timeout)
                   DefaultParity,    // Parity (typically no parity)
                   8,                // Data Bits
                   DefaultStopBits   // Stop Bits (typically one stop bit)
               );
    if (EFI_ERROR(Status)) {
        Print(L"Error: Failed to set serial port attributes: %r\n", Status);
        return;
    }
    Print(L"Serial port configured successfully.\n");

    // 3. Write data to the UART
    CHAR8 Message[] = "Hello from EDK II Serial Port!\n";
    UINTN MessageSize = sizeof(Message);
    Status = SerialIo->Write(SerialIo, &MessageSize, Message);
    if (EFI_ERROR(Status)) {
        Print(L"Error: Serial write failed: %r\n", Status);
        return ;
    }
    Print(L"Message sent to the serial port.\n");
    return;

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

  Print(L"Enable uart \n");

  GetSSDSerial();

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
//#ifdef SBC_BASEANSWER_TEST
//  CHAR8 *base_answer = "anti-tampering!?";
//  UINT8 devid[32] = {0,};
//  SBC_BaseAnswerValidate((UINT8 *)base_answer, strlen(base_answer));
//
//  SBC_GenDeviceID(devid);
//  SBC_external_mem_print_bin("Device ID", devid, sizeof devid);
//#endif
//
//#ifdef SBC_X509_TEST
//  SBC_X509TestMain();
//#endif
//
//  extern VOID SBC_FileCtrlTestMain(VOID);
//  SBC_FileCtrlTestMain();

    
   return EFI_SUCCESS;
}

