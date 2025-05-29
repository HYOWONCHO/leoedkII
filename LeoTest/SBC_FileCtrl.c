#include <Uefi.h>
#include <Library/UefiBootServicesTableLib.h>
#include <Library/UefiRuntimeServicesTableLib.h>
#include <Library/UefiLib.h>
#include <Library/BaseMemoryLib.h>
#include <Library/MemoryAllocationLib.h>
#include <Guid/FileInfo.h>
#include <Protocol/BlockIo.h>

#include <string.h>

#include "SBC_FileCtrl.h"



//SBCStatus  SBC_GetFileSize(IN CHAR16 *FileName, OUT *FileSize)
SBCStatus  SBC_GetFileSize(CHAR16 *FileName, UINTN  *FileSize)
{
    EFI_STATUS Status;

    EFI_HANDLE ImageHandle;
    EFI_SIMPLE_FILE_SYSTEM_PROTOCOL *FileSystem;
    EFI_FILE_PROTOCOL *Root;
    EFI_FILE_PROTOCOL *File;
    UINTN              InfoSize = 0;
    EFI_FILE_INFO     *FileInfo;

    if(SBC_FileSysFindHndl(&ImageHandle) <= 0) {
       
        eprint("SBC_FileSysFindHndl fail");
        return SBCFAIL;
    }

  Status = gBS->HandleProtocol(ImageHandle, 
                               &gEfiSimpleFileSystemProtocolGuid,
                               (VOID **)&FileSystem);
  if(EFI_ERROR(Status)) {
    DEBUG((DEBUG_INFO, " %a:%d Locate File Systam fail (%d) \r\n", 
           __FUNCTION__, __LINE__, Status));
    return SBCFAIL;
  }

  // Open the root directory of the volume.
  Status = FileSystem->OpenVolume(FileSystem, &Root);
  if (EFI_ERROR(Status)) {
    eprint("Failed to open volume: %r\n", Status);
    return SBCFAIL;
  }

  // Open the file using the provided Unicode file name.
  Status = Root->Open(Root, &File, FileName, EFI_FILE_MODE_READ, 0);
  if (EFI_ERROR(Status)) {
    eprint("Failed to open file %s: %r\n", FileName, Status);
    Root->Close(Root);
    return SBCFAIL;
  }

  // Query for the size of buffer needed to hold the file info.
  Status = File->GetInfo(File, &gEfiFileInfoGuid, &InfoSize, NULL);
  if (Status != EFI_BUFFER_TOO_SMALL) {
    eprint("Unexpected status when querying file info size: %r\n", Status);
    File->Close(File);
    Root->Close(Root);
    return SBCFAIL;
  }

  // Allocate memory for the file info structure.
  FileInfo = AllocatePool(InfoSize);
  if (FileInfo == NULL) {
    File->Close(File);
    Root->Close(Root);
    eprint("Allocate memory for the file info structure : EFI_OUT_OF_RESOURCES ");
    return SBCFAIL;
  }

  // Retrieve the file info.
  Status = File->GetInfo(File, &gEfiFileInfoGuid, &InfoSize, FileInfo);
  if (EFI_ERROR(Status)) {
    eprint("Failed to retrieve file info: %r\n", Status);
  } else {
    *FileSize = FileInfo->FileSize;
  }

  // Clean up allocated memory and open handles.
  FreePool(FileInfo);
  File->Close(File);
  Root->Close(Root);
  return SBCOK;

}

EFI_STATUS SBC_ReadFile(EFI_HANDLE ImageHandle, CHAR16 *FileNames, LV_t *out)
{
  EFI_STATUS Status;
  EFI_SIMPLE_FILE_SYSTEM_PROTOCOL *FileSystem;
  EFI_FILE_PROTOCOL *RootDir, *File;
//UINTN BufferSize = 128;
//CHAR8 Buffer[128];


  //TODO 
  // out buffer nill check
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
  Status = File->Read(File, (UINTN *)&out->length, out->value);
  if (EFI_ERROR(Status)) {
      DEBUG((DEBUG_INFO, " %a:%d File->Read fail (%d) \r\n", 
              __FUNCTION__, __LINE__, Status));
      //Print(L"File Content: %a\n", Buffer);
      return Status;
  }

  //out->length = BufferSize;
  //CopyMem(out->value, Buffer, out->length);
  
  //SBC_external_mem_print_bin((CHAR8 *)FileNames, (UINT8 *)out->value, (UINTN)out->length);

  // Close the file
  File->Close(File);
  RootDir->Close(RootDir);
  return Status;


}

EFI_STATUS SBC_WriteFile(EFI_HANDLE ImageHandle, CHAR16 *FileNames, LV_t *out)
{
  EFI_STATUS Status;
  EFI_SIMPLE_FILE_SYSTEM_PROTOCOL *FileSystem;
  EFI_FILE_PROTOCOL *RootDir, *File;
  //UINTN BufferSize = 128;
  //CHAR8 Buffer[128];


  //TODO 
  // out buffer nill check

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
  Status = RootDir->Open(RootDir, &File, FileNames, EFI_FILE_MODE_READ | EFI_FILE_MODE_WRITE, 0);
  if (EFI_ERROR(Status)) {
      DEBUG((DEBUG_INFO, " %a:%d RootDir->Open fail (%d) \r\n", 
     __FUNCTION__, __LINE__, Status));
    return Status;
  }

  // Read the file
  Status = File->Write(File, (UINTN *)&out->length, out->value);
  if (EFI_ERROR(Status)) {
      DEBUG((DEBUG_INFO, " %a:%d File->Read fail (%d) \r\n", 
              __FUNCTION__, __LINE__, Status));
      //Print(L"File Content: %a\n", Buffer);
      return Status;
  }



  // Close the file
  File->Close(File);
  RootDir->Close(RootDir);

  return Status;


}

UINTN  SBC_FileSysFindHndl(EFI_HANDLE *handle)
{

  EFI_STATUS Status;
  EFI_HANDLE *h;
  UINTN hdlcnt = 0;
   
  // Confirm that the Protocol Available
  Status = gBS->LocateHandleBuffer(ByProtocol,
                                   &gEfiSimpleFileSystemProtocolGuid,
                                   NULL,
                                   &hdlcnt,
                                   &h);
  if(EFI_ERROR(Status)) {
    dprint("Protocol not found (%d) \n", Status);
    return 0;
  }

  dprint("Protocol found (count : %d, Handle Buffer : 0x%p) \n",
        hdlcnt, *h);

  *handle = *h;
  return hdlcnt;
}


SBCStatus  SBC_CreateFile(EFI_HANDLE h, CHAR16 *fname)
{
    EFI_STATUS Status;
    EFI_SIMPLE_FILE_SYSTEM_PROTOCOL *FileSystem;
    EFI_FILE_PROTOCOL *RootDir, *File;

    //SBCLOGMSG("Starting");

    Status = gBS->HandleProtocol(h,
                               &gEfiSimpleFileSystemProtocolGuid,
                               (VOID **)&FileSystem);
    if(EFI_ERROR(Status)) {
        DEBUG((DEBUG_ERROR, "%a:%d HandleProtocol Fail \n",
               (CHAR8 *)__FUNCTION__, __LINE__));
        return SBCPROTO;
    }

    Status = FileSystem->OpenVolume(FileSystem, &RootDir);
    if(EFI_ERROR(Status)) {
        DEBUG((DEBUG_INFO, " %a:%d OpenVolume File Systam fail (%d) \r\n",
           __FUNCTION__, __LINE__, Status));
        return SBCBADFMT;
    }

    Status = RootDir->Open(RootDir, &File, fname,
                           EFI_FILE_MODE_READ |EFI_FILE_MODE_WRITE | EFI_FILE_MODE_CREATE,
                           0);
    if(EFI_ERROR(Status)) {
        DEBUG((DEBUG_INFO, " %a:%d RootDir->Open fail (%d) \r\n",
           __FUNCTION__, __LINE__, Status));
        return SBCBADFMT;
    }

    File->Close(File);

    return SBCOK;



}

SBCStatus  SBC_CreateDirectory(EFI_HANDLE h, CHAR16 *fname)
{
    EFI_STATUS Status;
    EFI_SIMPLE_FILE_SYSTEM_PROTOCOL *FileSystem;
    EFI_FILE_PROTOCOL *RootDir, *File;

    SBCLOGMSG("Starting");

    Status = gBS->HandleProtocol(h,
                               &gEfiSimpleFileSystemProtocolGuid,
                               (VOID **)&FileSystem);
    if(EFI_ERROR(Status)) {
        DEBUG((DEBUG_ERROR, "%a:%d HandleProtocol Fail \n",
               (CHAR8 *)__FUNCTION__, __LINE__));
        return SBCPROTO;
    }

    Status = FileSystem->OpenVolume(FileSystem, &RootDir);
    if(EFI_ERROR(Status)) {
        DEBUG((DEBUG_INFO, " %a:%d OpenVolume File Systam fail (%d) \r\n",
           __FUNCTION__, __LINE__, Status));
        return SBCBADFMT;
    }

    Status = RootDir->Open(RootDir, &File, fname,
                           EFI_FILE_MODE_READ |EFI_FILE_MODE_WRITE | EFI_FILE_MODE_CREATE,
                           EFI_FILE_DIRECTORY);
    if(EFI_ERROR(Status)) {
        DEBUG((DEBUG_INFO, " %a:%d RootDir->Open fail (%d) \r\n",
           __FUNCTION__, __LINE__, Status));
        return SBCBADFMT;
    }

    File->Close(File);

    return SBCOK;



}

SBCStatus  SBC_CheckAvailableBlkIODev(VOID)
{
    SBCStatus ret = SBCFAIL;

    EFI_HANDLE  *HandleBuffer;
    UINTN HandleCount; // Handle Count 
    EFI_STATUS Status;
    UINT8 Buffer[512];
    EFI_BLOCK_IO_PROTOCOL *BlockIo;


    // Verify that Block IO Protocol is available 
    Status = gBS->LocateHandleBuffer(
                                         ByProtocol,
                                         &gEfiBlockIoProtocolGuid, 
                                         NULL, 
                                         &HandleCount, 
                                         &HandleBuffer
    );

    if (EFI_ERROR(Status)) {

        // If no devices are found, check whether the correct drivers are loaded.
        Print(L"No Block IO device found ( %d )\n", Status);
        goto errdone;

    }
    else {
        Print(L"Found %d Block IO device \n" , HandleCount);
    }

    // Verify Block IO protocol binding
    Status = gBS->HandleProtocol(HandleBuffer[0], &gEfiBlockIoProtocolGuid, (VOID **)&BlockIo);
    if (EFI_ERROR(Status)) {
        Print(L"Failed to bind Block IO Protocol.(%d)\n",Status);
        goto errdone;
    }

    // Debug ReadBlock or WriteBlock
    Status = BlockIo->ReadBlocks(BlockIo, BlockIo->Media->MediaId, 0, sizeof(Buffer), Buffer);
    if (EFI_ERROR(Status)) {
        Print(L"Block read failed: %r\n", Status);
        goto errdone;
    } else {
        Print(L"Block read success.\n");
    }


    Print(L"Block Size: %d\n", BlockIo->Media->BlockSize);
    Print(L"Last Block: %lld\n", BlockIo->Media->LastBlock);
    Print(L"Media Present: %s\n", BlockIo->Media->MediaPresent ? L"Yes" : L"No");

    ret = SBCOK;

errdone:
    return ret;

}


VOID SBC_FileCtrlTestMain(VOID)
{
    SBCStatus ret = SBCOK;
    
    EFI_HANDLE ImageHandle = NULL;
    CHAR8 *wrmsg = "Hi, I am Leo, It is an pleasure, to meet you here xxxxx";
    UINTN wrmsgl = strlen(wrmsg);
    CHAR16 *fname = L"baseanswer.txt"; 
    //UINTN filesize = 0;

    UINT8 rdmsg[64] = {0, };
    LV_t rdlv;
    LV_t wrlv;

    // Length/Value structure initialize 
    _lv_set_data(&wrlv, wrmsg, wrmsgl);
    _lv_set_data(&rdlv, rdmsg, 0);

    // Must step) Find the File handle protocol for gEfiSimpleFileSystemProtocolGuid 
    if(SBC_FileSysFindHndl(&ImageHandle) <= 0) {
       
        eprint("SBC_FileSysFindHndl fail");
        return ;
    }

    ret =  SBC_CreateFile(ImageHandle, fname);
    if (ret != SBCOK) {
        eprint("%a file create fail", fname);
        return;
    }

     ret = SBC_WriteFile(ImageHandle, fname, &wrlv);
     if (ret != SBCOK) {
         eprint("%a frile write fail", fname);
         return;
     }


     SBC_GetFileSize(fname, (UINTN *)&rdlv.length);
     dprint("File size of %a : %d", fname, rdlv.length);

     

     ret = SBC_ReadFile(ImageHandle, fname, &rdlv);
     if (ret != SBCOK) {
         eprint("%a frile read fail", fname);
         return;
     }

     SBC_external_mem_print_bin("Read data", rdlv.value, rdlv.length);


     SBC_CheckAvailableBlkIODev();
     return;



}

