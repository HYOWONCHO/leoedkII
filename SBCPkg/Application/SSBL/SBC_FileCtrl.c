#include <Uefi.h>
#include <Library/UefiBootServicesTableLib.h>
#include <Library/UefiRuntimeServicesTableLib.h>
#include <Library/UefiLib.h>
#include <Library/BaseMemoryLib.h>
#include <Library/MemoryAllocationLib.h>
#include <Guid/FileInfo.h>
#include <Protocol/BlockIo.h>
#include <Protocol/DevicePathToText.h>
#include <Library/HandleParsingLib.h>
#include <Library/ShellLib.h>
//#include <Protocol/DevicePathToText.h>
#include <string.h>

#include <Library/DevicePathLib.h>
#include <Library/BaseCryptLib.h>

#include "SBC_Util.h"
#include "SBC_FileCtrl.h"
#include "SBC_BootProc.h"
#include "SBC_ProtectedSW.h"
#include "SBC_CryptAES.h"
#include "SBC_Kdf.h"
#include "SBC_AntiTampering.h"
#include "SBC_Config.h"

SBCStatus  SBC_RawPrtHeadRead(VOID *h, VOID *out)
{
    SBCStatus ret = SBCOK;
    //rawrpt_hdr_t *rawptr = (rawrpt_hdr_t *)out;
    //VOID *hblk = NULL;
    UINT32 bloblen = 0;
    UINT8 *blob = NULL;


    SBC_RET_VALIDATE_ERRCODEMSG((h != NULL), SBCNULLP, "Invalid Handle parametre");
    SBC_RET_VALIDATE_ERRCODEMSG((out != NULL), SBCNULLP, "Invalid parametre");

    bloblen = ALIGN_VALUE(sizeof(rawprt_hdr_t), SBC_RAWPRT_DFLT_BLK_SZ);
    blob = AllocateZeroPool(bloblen);
    SBC_RET_VALIDATE_ERRCODEMSG((blob != NULL), SBCNULLP, "Allocate fail for Blob");
    // Read the Raw Partition header form LBA 0 of NVMe ssd
    ret = SBC_RawPrtReadBlock(h, blob, &bloblen, SBC_RAW_PRTHDR_LBA);
    SBC_RET_VALIDATE_ERRCODEMSG((ret != SBCOK), ret, "Read raw partiton headr fail");

    CopyMem(out, (void *)blob, sizeof(rawprt_hdr_t));

    ret = SBCOK;

errdone:
    if (blob != NULL) {
        FreePool(blob);
    }
    return ret;

}

SBCStatus  SBC_FindFileBufHndl(UINT16 *f_path, UINTN *hndlcnt, VOID **hndl)
{
    EFI_STATUS  retval = EFI_SUCCESS;
    SBCStatus   ret = SBCOK;
    UINTN       idx = 0;

    SBC_RET_VALIDATE_ERRCODEMSG((f_path != NULL), SBCNULLP, "File Path obj Nill");
    SBC_RET_VALIDATE_ERRCODEMSG((*hndl != NULL), SBCNULLP, "Handle Obj Nill");

    for ( idx = 0; idx < *hndlcnt; idx++) {
        retval = SBC_IsFlieAccess(hndl[idx], f_path);
        if (EFI_ERROR(retval)) {
            continue;
        }

        break;
    }

    if (EFI_ERROR(retval)) {
        ret = SBCNOTFND;
        goto errdone;
    }

    *hndlcnt = idx;

errdone:
    return ret;

}


SBCStatus SBC_GetRawPrtImageLength(VOID *priv, UINTN lba, UINT32 *rdlen, UINTN offset)
{
    SBCStatus ret = SBCOK;
    UINT8 *buf = NULL;

    buf = AllocateZeroPool(*rdlen);
    SBC_RET_VALIDATE_ERRCODEMSG((buf != NULL), 
                                SBCNULLP, 
                                "Memory Allocation fail");



    ret = SBC_RawPrtReadBlock(priv,
                              (void *)buf,
                              rdlen,
                              lba);

    SBC_RET_VALIDATE_ERRCODEMSG((ret == SBCOK),
                                ret,
                                "Raw Partition read fail");

    CopyMem(rdlen, &buf[offset], 4);



errdone:
    return ret;
}



//SBCStatus  SBC_GetFileSize(IN CHAR16 *FileName, OUT *FileSize)
SBCStatus  SBC_GetFileSize(CHAR16 *FileName, UINTN  *FileSize)
{
    EFI_STATUS Status;

    EFI_HANDLE *ImageHandle;
    EFI_SIMPLE_FILE_SYSTEM_PROTOCOL *FileSystem;
    EFI_FILE_PROTOCOL *Root;
    EFI_FILE_PROTOCOL *File;
    UINTN              InfoSize = 0;
    EFI_FILE_INFO     *FileInfo;
    UINTN               hndlcnt;
    UINTN               idx;


    hndlcnt = SBC_FindEfiFileSystemProtocol(&ImageHandle);
    if (hndlcnt <= 0) {
        dprint("File Sys handle find fail : %d \n", hndlcnt);
        return SBCFAIL;
        //sbc_err_sysprn()
    }

    for (idx = 0; idx < hndlcnt; idx++) {
        Status = SBC_IsFlieAccess(ImageHandle[idx], FileName);
        if (EFI_ERROR(Status)) {
            //eprint("Is File (%r)", Status);
            continue;
        }

        break;
    }

    if (EFI_ERROR(Status)) {
        eprint("File %r", Status);
        return SBCFAIL;
    }


    Status = gBS->HandleProtocol(ImageHandle[idx],
                                   &gEfiSimpleFileSystemProtocolGuid,
                                   (VOID **)&FileSystem);
    if(EFI_ERROR(Status)) {
        DEBUG((DEBUG_ERROR, " %a:%d Locate File Systam fail (%r) \r\n",
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

    dprint("File Size : %d", *FileSize);

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
    //DEBUG((DEBUG_ERROR,"Image Handle : %p \r\n", ImageHandle));
    //DEBUG((DEBUG_ERROR,"Read File : %s \r\n", (CHAR8 *)FileNames));

  //dprint("Read File : %s", FileNames);

  // Locate file system
  Status = gBS->HandleProtocol(ImageHandle,
                               &gEfiSimpleFileSystemProtocolGuid,
                               (VOID **)&FileSystem);
  if(EFI_ERROR(Status)) {
    DEBUG((DEBUG_ERROR, " %a:%d Locate File Systam fail (%r) \r\n",
           __FUNCTION__, __LINE__, Status));
    return Status;
  }

  // Open the roor directory
  Status = FileSystem->OpenVolume(FileSystem, &RootDir);
  if (EFI_ERROR(Status)) {
        DEBUG((DEBUG_ERROR, " %a:%d OpenVolume File Systam fail (%r) \r\n",
           __FUNCTION__, __LINE__, Status));
    return Status;
  }

  // Open the file
  Status = RootDir->Open(RootDir, &File, FileNames, EFI_FILE_MODE_READ, 0);
  if (EFI_ERROR(Status)) {
      DEBUG((DEBUG_ERROR, " %a:%d RootDir->Open fail (%r) \r\n",
     __FUNCTION__, __LINE__, Status));
    return Status;
  }

  // Read the file
  Status = File->Read(File, (UINTN *)&out->length, out->value);
  if (EFI_ERROR(Status)) {
      DEBUG((DEBUG_ERROR, " %a:%d File->Read fail (%r) \r\n",
              __FUNCTION__, __LINE__, Status));
      //dprint("File Content: %a\n", Buffer);
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

  ////dprint(");

  //TODO
  // out buffer nill check

  // Locate file system
  Status = gBS->HandleProtocol(ImageHandle,
                               &gEfiSimpleFileSystemProtocolGuid,
                               (VOID **)&FileSystem);
  ////dprint(");
  if(EFI_ERROR(Status)) {
    DEBUG((DEBUG_ERROR, " %a:%d Locate File Systam fail (%r) \r\n",
           __FUNCTION__, __LINE__, Status));
    return Status;
  }

  ////dprint(");
  // Open the roor directory
  Status = FileSystem->OpenVolume(FileSystem, &RootDir);
  if (EFI_ERROR(Status)) {
        DEBUG((DEBUG_ERROR, " %a:%d OpenVolume File Systam fail (%r) \r\n",
           __FUNCTION__, __LINE__, Status));
    return Status;
  }

  ////dprint(");
  // Open the file
  Status = RootDir->Open(RootDir, &File, FileNames, EFI_FILE_MODE_READ | EFI_FILE_MODE_WRITE | EFI_FILE_MODE_CREATE, 0);
  if (EFI_ERROR(Status)) {
      DEBUG((DEBUG_ERROR, " %a:%d RootDir->Open fail (%r) \r\n",
     __FUNCTION__, __LINE__, Status));
      ////dprint(");
      RootDir->Close(RootDir);
    return Status;
  }

  ////dprint(");
  // Read the file
  Status = File->Write(File, (UINTN *)&out->length, out->value);
  if (EFI_ERROR(Status)) {
      ////dprint(");
      DEBUG((DEBUG_ERROR, " %a:%d File->Write fail (%r) \r\n",
              __FUNCTION__, __LINE__, Status));
      //dprint("File Content: %a\n", Buffer);

      File->Close(File);
      RootDir->Close(RootDir);
      return Status;
  }

  ////dprint(");


  // Close the file
  File->Close(File);
  RootDir->Close(RootDir);

  return Status;


}

//extern EFI_HANDLE sbcImgHandle;
EFI_STATUS SBC_IsFlieAccess(EFI_HANDLE ImageHandle, CHAR16 *FileNames)
{
    EFI_STATUS  retval = EFI_SUCCESS;
    EFI_SIMPLE_FILE_SYSTEM_PROTOCOL *FileSystem;
    EFI_FILE_PROTOCOL *RootDir = NULL;
    EFI_FILE_PROTOCOL *File = NULL;

    //gImageHandle = NULL:

    retval = gBS->HandleProtocol(ImageHandle,
                                 &gEfiSimpleFileSystemProtocolGuid,
                                 (VOID **)&FileSystem);
    
    if (EFI_ERROR(retval)) {
        eprint("Locate file system handle fail (%r)", retval);
        goto errdone;
    }

    retval = FileSystem->OpenVolume(FileSystem, &RootDir);
    if (EFI_ERROR(retval)) {
        eprint("OpenVolume fail (%r)", retval);
        goto errdone;
    }

    retval = RootDir->Open(RootDir, &File, FileNames, EFI_FILE_MODE_READ,  0);



errdone:
    if (File != NULL) {
        File->Close(File);
    }
    return retval; 
    
}

BOOLEAN SBC_IsDirExist(EFI_HANDLE ImageHandle, CHAR16 *DirectoryName)
{
  EFI_STATUS                 Status;
  EFI_SIMPLE_FILE_SYSTEM_PROTOCOL *FileSystem;
  EFI_FILE_PROTOCOL          *RootFile;
  EFI_FILE_PROTOCOL          *TargetDirectory;
  EFI_FILE_INFO              *FileInfo;
  BOOLEAN                    Exists = FALSE;
  UINTN                      FileInfoSize;


  
    Status = gBS->HandleProtocol(ImageHandle,
                                 &gEfiSimpleFileSystemProtocolGuid,
                                 (VOID **)&FileSystem);

    if (EFI_ERROR(Status)) {
        eprint("Locate file system handle fail (%r)", Status);
        return FALSE;
        //goto errdone;
    }

  // 1. Open the root directory of the file system volume
  Status = FileSystem->OpenVolume (FileSystem, &RootFile);
  if (EFI_ERROR(Status)) {
    DEBUG ((DEBUG_ERROR, "DirectoryExists: Failed to open volume. Status: %r\n", Status));
    return FALSE;
  }

  // 2. Try to open the target directory
  //    EFI_FILE_MODE_READ for read access
  //    EFI_FILE_DIRECTORY if we expect it to be a directory
  Status = RootFile->Open (
                       RootFile,
                       &TargetDirectory,
                       DirectoryName,
                       EFI_FILE_MODE_READ,
                       EFI_FILE_DIRECTORY // Expecting a directory
                       );

  if (EFI_ERROR(Status)) {
    // If opening failed, it likely doesn't exist or isn't a directory
    DEBUG ((DEBUG_INFO, "DirectoryExists: Failed to open '%s'. Status: %r\n", DirectoryName, Status));
    // Close the RootFile handle before returning
    RootFile->Close (RootFile);
    return FALSE;
  }

  // 3. If opened successfully, get its information to confirm it's a directory
  //    First call with NULL buffer to get required size
  FileInfoSize = 0;
  Status = TargetDirectory->GetInfo (
                             TargetDirectory,
                             &gEfiFileInfoGuid,
                             &FileInfoSize,
                             NULL
                             );

  if (Status == EFI_BUFFER_TOO_SMALL) {
    FileInfo = AllocatePool (FileInfoSize);
    if (FileInfo == NULL) {
      DEBUG ((DEBUG_ERROR, "DirectoryExists: Failed to allocate FileInfo buffer.\n"));
      // Close handles before returning
      TargetDirectory->Close (TargetDirectory);
      RootFile->Close (RootFile);
      return FALSE;
    }

    Status = TargetDirectory->GetInfo (
                               TargetDirectory,
                               &gEfiFileInfoGuid,
                               &FileInfoSize,
                               FileInfo
                               );
    if (EFI_ERROR(Status)) {
      DEBUG ((DEBUG_ERROR, "DirectoryExists: Failed to get file info. Status: %r\n", Status));
    } else {
      // 4. Check if the EFI_FILE_DIRECTORY attribute is set
      if ((FileInfo->Attribute & EFI_FILE_DIRECTORY) == EFI_FILE_DIRECTORY) {
          dprint("FNAME : %s", FileInfo->FileName);
        Exists = TRUE;
      } else {
        DEBUG ((DEBUG_INFO, "DirectoryExists: '%s' exists but is not a directory.\n", DirectoryName));
      }
    }
    FreePool (FileInfo);
  } else {
    DEBUG ((DEBUG_ERROR, "DirectoryExists: Failed to get file info size. Status: %r\n", Status));
  }

  // 5. Close all opened handles
  TargetDirectory->Close (TargetDirectory);
  RootFile->Close (RootFile);

  return Exists;
    
}

EFI_STATUS SBC_LogWriteFile(EFI_HANDLE ImageHandle, CHAR16 *FileNames, LV_t *out)
{
  EFI_STATUS Status;
  //SBCStatus ret = SBCOK;
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
    DEBUG((DEBUG_ERROR, " %a:%d Locate File Systam fail (%r) \r\n",
           __FUNCTION__, __LINE__, Status));
    return Status;
  }

  // Open the roor directory
  Status = FileSystem->OpenVolume(FileSystem, &RootDir);
  if (EFI_ERROR(Status)) {
        DEBUG((DEBUG_ERROR, " %a:%d OpenVolume File Systam fail (%r) \r\n",
           __FUNCTION__, __LINE__, Status));
    return Status;
  }




  // Open the file
  Status = RootDir->Open(RootDir, &File, FileNames, EFI_FILE_MODE_READ | EFI_FILE_MODE_WRITE , 0);
  if (EFI_ERROR(Status)) {
      DEBUG((DEBUG_ERROR, " %a:%d RootDir->Open fail (%r) \r\n",
     __FUNCTION__, __LINE__, Status));
    return Status;
  }

  // Set to End position
  File->SetPosition(File, (UINT64)-1);
  // Read the file
  Status = File->Write(File, (UINTN *)&out->length, out->value);
  if (EFI_ERROR(Status)) {
      DEBUG((DEBUG_ERROR, " %a:%d File->Read fail (%r) \r\n",
              __FUNCTION__, __LINE__, Status));
      //dprint("File Content: %a\n", Buffer);
      return Status;
  }



  // Close the file
  File->Close(File);
  RootDir->Close(RootDir);

  return Status;


}

UINTN SBC_FindEfiFileSystemProtocol(EFI_HANDLE **handle)
{
    //EFI_HANDLE *Handles = *handle;

    EFI_STATUS  retval;
    UINTN HandleCount;

    retval = gBS->LocateHandleBuffer(ByProtocol, &gEfiSimpleFileSystemProtocolGuid, NULL, &HandleCount, handle);
    if (EFI_ERROR(retval)) {
        dprint("gEfiSimpleFileSystemProtocolGuid foud fail (%r) \n", retval);
        return 0;
    }

    return HandleCount;
}

UINTN  SBC_FileSysFindHndl(EFI_HANDLE *handle)
{

    UINTN hdlcnt = 0;
    EFI_STATUS Status;
    EFI_HANDLE *h;


    // Confirm that the Protocol Available
    Status = gBS->LocateHandleBuffer(ByProtocol,
                                     &gEfiSimpleFileSystemProtocolGuid,
                                     NULL,
                                     &hdlcnt,
                                     &h);
    if(EFI_ERROR(Status)) {
      dprint("Protocol not found (%r) \n", Status);
      return 0;
    }

    //dprint("Protocol found (count : %d, Handle Buffer : 0x%p) \n",
    //      hdlcnt, *h);

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
        DEBUG((DEBUG_ERROR, " %a:%d OpenVolume File Systam fail (%r) \r\n",
           __FUNCTION__, __LINE__, Status));
        return SBCBADFMT;
    }

    Status = RootDir->Open(RootDir, &File, fname,
                           EFI_FILE_MODE_READ |EFI_FILE_MODE_WRITE | EFI_FILE_MODE_CREATE,
                           0);
    if(EFI_ERROR(Status)) {
        DEBUG((DEBUG_ERROR, " %a:%d RootDir->Open fail (%r) \r\n",
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
        DEBUG((DEBUG_ERROR, " %a:%d OpenVolume File Systam fail (%r) \r\n",
           __FUNCTION__, __LINE__, Status));
        return SBCBADFMT;
    }

    Status = RootDir->Open(RootDir, &File, fname,
                           EFI_FILE_MODE_READ |EFI_FILE_MODE_WRITE | EFI_FILE_MODE_CREATE,
                           EFI_FILE_DIRECTORY);
    if(EFI_ERROR(Status)) {
        DEBUG((DEBUG_ERROR, " %a:%d RootDir->Open fail (%r) \r\n",
           __FUNCTION__, __LINE__, Status));
        return SBCBADFMT;
    }

    File->Close(File);

    return SBCOK;



}

static UINT32 _sbc_bm_lookup_key(CHAR8* key)
{
    bm_lookup_table_t tb[] =  {
        {BOOT_MODE_STRNRORMAL, BOOT_MODE_NORMAL},
        {BOOT_MODE_STRUPDATE, BOOT_MODE_UPDATE},
        {BOOT_MODE_STRFACTORY, BOOT_MODE_FACTORY}
    };

    UINT32 nkeys = (sizeof(tb) / sizeof(bm_lookup_table_t));

    //dprint("key : %a , keylen :%d", key, strlen(key));
    for (INT32 x = 0; x < nkeys; x++) {
        bm_lookup_table_t *sym = &tb[x];
        //dprint("sym key : %a , Len :%d", sym->key, strlen(sym->key));
        if (strncmp(sym->key, key, strlen(sym->key) - 1) == 0) {
            return sym->val;
        }
    }

    return BOOT_MODE_UNKNOWN;
}

UINT32  SBC_ReadBootMode(VOID)
{
    UINT32 ret = BOOT_MODE_UNKNOWN;

    EFI_HANDLE      fhnd = NULL;
    UINT8           rdbuf[16] = {0,};
    LV_t            rdlv;
    

    if (SBC_FileSysFindHndl(&fhnd) <= 0) {
        eprint("SBC File Handle Protocol found fail");
        ret = BOOT_MODE_UNKNOWN;
        goto errdone;
    }

    SBC_RET_VALIDATE_ERRCODEMSG((fhnd != NULL), SBCNULLP, "File Handle Obj Nill");

    _lv_set_data(&rdlv, rdbuf, 16);
    ret = SBC_ReadFile(fhnd, BOOT_MODE_FNAME, &rdlv);
    if (ret != SBCOK) {
        eprint("Boot Mode file read fail");
        ret = BOOT_MODE_UNKNOWN;
        goto errdone;
    }

    dprint("Boot Mode : %a", rdbuf);
    //dprint("Read Boot Mode : %s \n", rdbuf);

    switch (_sbc_bm_lookup_key((CHAR8 *)rdbuf)) {
    case BOOT_MODE_NORMAL:
        ret = BOOT_MODE_NORMAL;
        break;
    case BOOT_MODE_UPDATE:
        ret = BOOT_MODE_UPDATE;
        break;
    case BOOT_MODE_FACTORY:
        ret = BOOT_MODE_FACTORY;
        break;
    default:
        ret = BOOT_MODE_UNKNOWN;
        break;
    }

errdone:
    return ret;

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
        dprint("No Block IO device found ( %d )\n", Status);
        goto errdone;

    }
//  else {
//      dprint("Found %d Block IO device \n" , HandleCount);
//  }

    // Verify Block IO protocol binding
    Status = gBS->HandleProtocol(HandleBuffer[0], &gEfiBlockIoProtocolGuid, (VOID **)&BlockIo);
    if (EFI_ERROR(Status)) {
        dprint("Failed to bind Block IO Protocol.(%r)\n",Status);
        goto errdone;
    }

    // Debug ReadBlock or WriteBlock
    Status = BlockIo->ReadBlocks(BlockIo, BlockIo->Media->MediaId, 0, sizeof(Buffer), Buffer);
    if (EFI_ERROR(Status)) {
        dprint("Block read failed: %r\n", Status);
        goto errdone;
    } else {
        dprint("Block read success.\n");
    }


    dprint("Block Size: %d\n", BlockIo->Media->BlockSize);
    dprint("Last Block: %lld\n", BlockIo->Media->LastBlock);
    dprint("Media Present: %s\n", BlockIo->Media->MediaPresent ? L"Yes" : L"No");

    ret = SBCOK;

  errdone:
    return ret;

}






void _sfc_init_info_parse(IN VOID *inbuf, OUT VOID *outbuf)
{
    UINT8 *p = NULL;
    UINT8 *retbuf = NULL;

    sbc_rptn_header_t h;

    ZeroMem((void *)&h, sizeof h);
    p = (UINT8 *)inbuf;
    retbuf = (UINT8 *)outbuf;
    CopyMem(h.value, (UINT8 *)p, sizeof h);

    SBC_mem_print_bin("Header Skip Info", h.m.skip, 64 );
    SBC_mem_print_bin("Header Real Info", h.m.info, 64 );

    // What TO DO
    // 1. Extract related the Prt infomation

    // 2. Copy the result to outbuf buffer

    // This two-line MUST remove into this function, later.
    retbuf++; // Error ignore code
    p++; // Error ignore code 



    //return;


}

SBCStatus SBC_ReadRawPrtHeaderInfo(VOID *blkhnd, VOID *rdbuf,  UINT32 *rdlen)
{
    SBCStatus       ret = SBCOK;
    EFI_STATUS      retval;
    EFI_BLOCK_IO_PROTOCOL           *blkio = NULL;
    VOID *readbuf = NULL;

    SBC_RET_VALIDATE_ERRCODEMSG(((rdbuf != NULL) || (rdlen != NULL)), SBCNULLP, "Invalid parameter");
    SBC_RET_VALIDATE_ERRCODEMSG((*rdlen != 0), SBCZEROL, "Invalid parameter");

    blkio  = (EFI_BLOCK_IO_PROTOCOL *)blkhnd;

    *rdlen = ALIGN_VALUE(*rdlen, blkio->Media->BlockSize);
    readbuf = AllocateZeroPool(*rdlen);
    if (readbuf == NULL) {
        dprint("Allocate Pool fail \n");
        ret = SBCNULLP;
        goto errdone;
    }

    retval = blkio->ReadBlocks(
                blkio,
                blkio->Media->MediaId,
                0,
                *rdlen,
                readbuf
        );

    if (EFI_ERROR(retval)) {
        dprint("Read Heade Info fail(%r) %r \n", retval, retval);
        ret = SBCIO;
        goto errdone;
    }

    //SBC_mem_print_bin("Read Buf", readbuf, SBC_RPTN_INFO_LEN << 1);
    //CopyMem(rdbuf, readbuf, SBC_RPTN_INFO_LEN << 1);
    
    //SBC_mem_print_bin("Rd Bud", rdbuf, SBC_RPTN_INFO_LEN << 1);
    //dprint("Read info result %r (Block Size : %d)\n" , retval, blkio->Media->BlockSize);
    //SBC_RET_VALIDATE_ERRCODEMSG((retval == EFI_SUCCESS), SBCIO, "LBA 0 READ BLOCK FAIL");


    _sfc_init_info_parse(readbuf, rdbuf);


    

errdone:

    if (readbuf != NULL) {
        FreePool(readbuf);
        readbuf = NULL;
    }
    return ret;


}

SBCStatus SBC_RawPrtReadBlock(VOID *blkhnd, VOID *rdbuf,  UINT32 *rdlen, UINTN rlba)
{
    SBCStatus       ret = SBCOK;
    EFI_STATUS      retval;
    EFI_BLOCK_IO_PROTOCOL           *blkio = NULL;
//    VOID *readbuf = NULL;
//    UINTN   blklen = 0LU;

    //dprint("%a:%d \n",__FUNCTION__, __LINE__);
    SBC_RET_VALIDATE_ERRCODEMSG((blkhnd != NULL), SBCNULLP, "Block IO Handle Nill");
    SBC_RET_VALIDATE_ERRCODEMSG(((rdbuf != NULL) || (rdlen != NULL)), SBCNULLP, "Invalid parameter");
    SBC_RET_VALIDATE_ERRCODEMSG((*rdlen != 0), SBCZEROL, "Invalid parameter");

    blkio  = (EFI_BLOCK_IO_PROTOCOL *)blkhnd;

    

//  blklen = ALIGN_VALUE(*rdlen, blkio->Media->BlockSize);
//  //dprint("BLK Len : %d \n", blklen);
//  readbuf = AllocateZeroPool(blklen);
//  if (readbuf == NULL) {
//      dprint("Allocate Pool fail \n");
//      ret = SBCNULLP;
//      goto errdone;
//  }


//  dprint("Handle %p, Media Id, %ld, lba : %ld, Len : %ld, rdbuf : %p",
//         blkio,
//         blkio->Media->MediaId,
//         rlba,
//         *rdlen,
//         rdbuf);

    retval = blkio->ReadBlocks(
                blkio,
                blkio->Media->MediaId,
                rlba,
                *rdlen,
                rdbuf
        );

    if (EFI_ERROR(retval)) {
        dprint("Read Heade Info fail(%r) %r \n", retval, retval);
        ret = SBCIO;
        goto errdone;
    }
    //SBC_mem_print_bin("Read Buf", readbuf, *rdlen);
    //CopyMem(rdbuf, readbuf, *rdlen);
    
    //SBC_mem_print_bin("Rd Bud", rdbuf, SBC_RPTN_INFO_LEN << 1);
    //dprint("Read info result %r (Block Size : %d)\n" , retval, blkio->Media->BlockSize);
    //SBC_RET_VALIDATE_ERRCODEMSG((retval == EFI_SUCCESS), SBCIO, "LBA 0 READ BLOCK FAIL");


    //_sfc_init_info_parse(readbuf, rdbuf);



errdone:
//  if (readbuf != NULL) {
//      FreePool(readbuf);
//      readbuf = NULL;
//  }
    return ret;


}
 

SBCStatus  SBC_RawPrtBlockWrite(VOID *blkio, UINT8 *wrbuf, UINT32 wrlen, UINT32 wrlba)
{
    SBCStatus ret = SBCOK;
    EFI_STATUS retval = EFI_SUCCESS;
    EFI_BLOCK_IO_PROTOCOL           *p = NULL;

    SBC_RET_VALIDATE_ERRCODEMSG(((p != NULL) || (wrbuf != NULL)), SBCNULLP, "Invalid Parameter");
    SBC_RET_VALIDATE_ERRCODEMSG((wrlen != 0), SBCZEROL, "Invalid Parameter");

    p = (EFI_BLOCK_IO_PROTOCOL *)blkio;

    retval = p->WriteBlocks(
                    p,
                    p->Media->MediaId,
                    wrlba,
                    wrlen ,
                    //(wrlen % p->Media->BlockSize == 0) ? wrlen : p->Media->BlockSize ,
                    wrbuf
        );

    if(EFI_ERROR(retval)) {
        dprint("Write Block I/O fail : %r", retval);
        ret = SBCIO;
        goto errdone;
    }

errdone:
    return ret;

}


SBCStatus SBC_ProtectedSWWrite(VOID *blkio, 
                              VOID *buf, UINT32 *len, 
                              UINT32 bnkid)
{
    SBCStatus ret = SBCOK;
    UINT32 wrlen = 0;
    //UINT8 wrbuf[SBC_RAWPRT_DFLT_BLK_SZ] = {0, };
    UINT8 *w_buf = NULL;

    UINTN   wrlba = 0;

    SBC_RET_VALIDATE_ERRCODEMSG((blkio != NULL), SBCNULLP, "Object NULL");
    SBC_RET_VALIDATE_ERRCODEMSG((buf != NULL), SBCNULLP, "Object NULL");
    SBC_RET_VALIDATE_ERRCODEMSG((len != NULL), SBCNULLP, "Object NULL");


    wrlen = *(UINT32 *)len;

    wrlba = (BOOT_FW_PROT_SW_POS << (bnkid - 1)) >> SBC_RAWPRT_DFLT_SHIFT;
    dprint("%d bank Protected SW Address (0x%x)", bnkid, wrlba);
    wrlba <<= SBC_RAWPRT_DFLT_SHIFT;

    wrlen = ALIGN_VALUE(wrlen + 4, 512);

    dprint("%d bank Protected SW Len %ld", bnkid, wrlen);

    w_buf = AllocateZeroPool(wrlen + 4);
    SBC_RET_VALIDATE_ERRCODEMSG((w_buf != NULL), 
                                SBCNULLP,
                                "Protect SW write buffer Nill");


    CopyMem(&w_buf[0], &wrlen, 4);
    CopyMem(&w_buf[4], buf, (UINTN)len);


   
    ret = SBC_RawPrtBlockWrite(blkio,
                               buf,
                               wrlen,
                               wrlba);

    SBC_RET_VALIDATE_ERRCODEMSG((ret == SBCOK),
                                ret,
                                "Protected SW write fail");

    *(UINT32 *)len = wrlen;
errdone:

    return ret;

}

SBCStatus SBC_ProtectedSWRead(VOID *blkio, 
                              VOID **buf, UINT32 *len, 
                              UINT32 bnkid)
{
    SBCStatus ret = SBCOK;
    UINT32 rdlen = 0;
    UINT8 rdbuf[SBC_RAWPRT_DFLT_BLK_SZ] = {0, };

    UINTN   rdlba = 0;

    SBC_RET_VALIDATE_ERRCODEMSG((blkio != NULL), SBCNULLP, "Object NULL");
    SBC_RET_VALIDATE_ERRCODEMSG((buf != NULL), SBCNULLP, "Object NULL");
    SBC_RET_VALIDATE_ERRCODEMSG((len != NULL), SBCNULLP, "Object NULL");


    rdlen = SBC_RAWPRT_DFLT_BLK_SZ;

    // ((0x01C0_0200 << ( Validate Bank - 1 )) >> 9
    //Bank 1 Lba = 57345
    //Bank 2 Lba  = 114690

    rdlba = (BOOT_FW_PROT_SW_POS << (bnkid - 1)) >> SBC_RAWPRT_DFLT_SHIFT;
    dprint("%d bank Protected SW Address (0x%x)", bnkid, rdlba);
    rdlba <<= SBC_RAWPRT_DFLT_SHIFT;

    ret = SBC_RawPrtReadBlock(blkio,
                                rdbuf, 
                                &rdlen,
                                rdlba);

    SBC_RET_VALIDATE_ERRCODEMSG((ret == SBCOK), 
                                ret , 
                                "Protected SW header read fail");

    CopyMem((void *)&rdlen, rdbuf, sizeof(rdlba));

    if (rdlen <= 0) {
        // It is error and Protected SW is not exist in Raw Partition
        ret = SBCZEROL;
        goto errdone;
    }

    dprint("%d bank Protected SW Len %ld", bnkid, rdlen);

    rdlen = ALIGN_VALUE(*(UINT32 *)len, 512);
    *buf = AllocateZeroPool(rdlen);
    SBC_RET_VALIDATE_ERRCODEMSG((*buf != NULL), 
                                SBCNULLP, 
                                "Read Buff Nill");


    
    ret = SBC_RawPrtReadBlock(blkio,
                              *buf,
                              &rdlen,
                              rdlba);

    SBC_RET_VALIDATE_ERRCODEMSG((ret == SBCOK), 
                                ret , 
                                "Protected SW  read fail");

    *(UINT32 *)len = rdlen;

    return ret;
errdone:

    *(UINT32 *)len = 0;

    if (*buf != NULL) {
        FreePool(*buf);
        *buf = NULL;
    }

    return ret;

}

SBCStatus  SBC_BlkIoHandleInit(OUT VOID **hblk, OUT VOID *hdr)
{
#define     SBC_MAGIC_LEN           0x04
#define     SBC_MAGIC_ID            0xAA55AA55

    SBCStatus                       ret = SBCFAIL;
    EFI_STATUS                      Status;
    EFI_HANDLE                      *HandleBuffer = NULL;
    UINTN                           NumberOfHandles;
    VOID                            *ReadBuffer = NULL; // Buffer for raw block data
    EFI_BLOCK_IO_PROTOCOL           *BlockIo = NULL;
    [[maybe_unused]] UINT32                           magicid = 0UL;
   // UINT64                           blkiosz;

    SBC_RET_VALIDATE_ERRCODEMSG((hblk != NULL), SBCNULLP, "Invalid Parameter");


    Status = gBS->LocateHandleBuffer(
                    ByProtocol,
                    &gEfiBlockIoProtocolGuid,
                    NULL,
                    &NumberOfHandles,
                    &HandleBuffer
        );

    if (EFI_ERROR(Status)) {
        dprint("ERROR: Failed to locate BlockIoProtocol handles: %r\n", Status);
        SBC_RET_VALIDATE_ERRCODEMSG((Status != EFI_SUCCESS), SBCFAIL, "ERROR: Failed to locate BlockIoProtocol handles");
    }

    //dprint("Found %d Block I/O Protocol handles.\n", NumberOfHandles);

    for (int idx = 0; idx < NumberOfHandles; idx++) {

        // Get the Block I/O protocol interfcae!cp
        Status = gBS->HandleProtocol(
                        HandleBuffer[idx],
                        &gEfiBlockIoProtocolGuid,
                        (VOID **)&BlockIo
            );

        if (EFI_ERROR(Status)) {
            dprint("RROR: Could not open BlockIoProtsocol %r\n", Status);
            SBC_RET_VALIDATE_ERRCODEMSG((Status != EFI_SUCCESS), SBCFAIL, "ERROR: Could not open BlockIoProtocol");
        }

        //blkiosz = MultU64x32(BlockIo->Media->LastBlock + 1, BlockIo->Media->BlockSize);
        //dprint("Found %p Block I/O Protocol Address.\n", BlockIo);


        //dprint("INFO: Found SBC Raw Partiiton %r\n", Status);

        ReadBuffer = AllocatePool(BlockIo->Media->BlockSize);
        if (ReadBuffer == NULL) {
             dprint("Buffer allocatino fail \n");
             ret = SBCNULLP;
             goto errdone;
        }


        Status = BlockIo->ReadBlocks(
                         BlockIo,
                         BlockIo->Media->MediaId,
                         0, // LBA 0
                         BlockIo->Media->BlockSize,
                         ReadBuffer
                         );

        if (EFI_ERROR(Status)) {
//          dprint("ERROR: Failed to read LBA 0: %r\n", Status);
//          SBC_RET_VALIDATE_ERRCODEMSG((Status != EFI_SUCCESS), SBCFAIL, "ERROR: Could not open BlockIoProtocol");
//          ret = SBCFAIL;
//          goto errdone;

            continue;
        }

        //SBC_mem_print_bin("Read Block", (UINT8 *)ReadBuffer, SBC_MAGIC_LEN);
        //CopyMem((void *)&magicid, (VOID *)&((UINT8 *)ReadBuffer)[0],SBC_MAGIC_LEN);
        CopyMem((void *)hdr, (VOID *)&((UINT8 *)ReadBuffer)[0], sizeof(rawprt_hdr_t));


        //SBC_mem_print_bin("Header buf", (UINT8 *)hdr, 16);

        FreePool(ReadBuffer);      

        //((rawprt_hdr_t *)hdr)->magicid  = SBC_SWAP_ENDIAN_32(((rawprt_hdr_t *)hdr)->magicid);
        //dprint("%d Magic ID : 0x%x \n", idx, ((rawprt_hdr_t *)hdr)->magicid);

        
        
        if (((rawprt_hdr_t *)hdr)->magicid != SBC_RAWPRT_MAGIC_ID) {
            continue;
        }

        *hblk = (VOID *)BlockIo;
        dprint("Found %p Block I/O Protocol Address Magci ID : 0x%x.\n", BlockIo, magicid);
        //dprint("0x%p SBC Raw Buffer MagicID found !!! \n", *hblk);


        ret = SBCOK;
        break;
    }

errdone:
    return ret;

}

//EFI_STATUSFv
//EFIAPI
//RawPrtAccessSample (
//  IN EFI_HANDLE        ImageHandle,
//  IN EFI_SYSTEM_TABLE  *SystemTable
//  )
//{
//  EFI_STATUS                      Status = EFI_SUCCESS;
//  EFI_HANDLE                      *HandleBuffer = NULL;
//  UINTN                           NumberOfHandles;
//  UINTN                           Index;
//  EFI_BLOCK_IO_PROTOCOL           *BlockIo = NULL;
//  EFI_DEVICE_PATH_PROTOCOL        *DevicePath = NULL;
//  EFI_DEVICE_PATH_TO_TEXT_PROTOCOL *DevicePathToText = NULL;
//  CHAR16                          *DevicePathStr = NULL;
//  VOID                            *ReadBuffer = NULL; // Buffer for raw block data
//
//  dprint("Enumerating block devices...\n");
//
//  //
//  // 1. Locate all handles that support the EFI_BLOCK_IO_PROTOCOL.
//  //
//  Status = gBS->LocateHandleBuffer (
//                  ByProtocol,
//                  &gEfiBlockIoProtocolGuid,
//                  NULL,
//                  &NumberOfHandles,
//                  &HandleBuffer
//                  );
//  if (EFI_ERROR (Status)) {
//    dprint("ERROR: Failed to locate BlockIoProtocol handles: %r\n", Status);
//    return Status;
//  }
//
//  dprint("Found %d Block I/O Protocol handles.\n", NumberOfHandles);
//
//  // (Optional) Locate DevicePathToTextProtocol for printing
//  gBS->LocateProtocol (&gEfiDevicePathToTextProtocolGuid, NULL, (VOID **)&DevicePathToText);
//
//  //
//  // 2. Iterate through each handle and get Block IO information.
//  //
//  for (Index = 0; Index < NumberOfHandles; Index++) {
//    dprint("\n--- Handle %d ---\n", Index);
//
//    // Get the Block I/O Protocol interface
//    Status = gBS->HandleProtocol (
//                    HandleBuffer[Index],
//                    &gEfiBlockIoProtocolGuid,
//                    (VOID **)&BlockIo
//                    );
//    if (EFI_ERROR (Status)) {
//      dprint("  ERROR: Could not open BlockIoProtocol: %r\n", Status);
//      continue;
//    }
//
//    // Get the Device Path for identification
//    Status = gBS->HandleProtocol (
//                    HandleBuffer[Index],
//                    &gEfiDevicePathProtocolGuid,
//                    (VOID **)&DevicePath
//                    );
//    if (EFI_ERROR (Status)) {
//      dprint("  WARNING: No Device Path Protocol for this handle: %r\n", Status);
//      DevicePath = NULL; // Ensure it's NULL if not found
//    }
//
//    // Print device path string (if protocol available)
//    if (DevicePath != NULL && DevicePathToText != NULL) {
//      DevicePathStr = DevicePathToText->ConvertDevicePathToText (DevicePath, FALSE, FALSE);
//      if (DevicePathStr != NULL) {
//        dprint("  Device Path: %s\n", DevicePathStr);
//        FreePool(DevicePathStr);
//        DevicePathStr = NULL; // Reset for next iteration
//      }
//    } else if (DevicePath != NULL) {
//      dprint("  Device Path present, but DevicePathToTextProtocol not found.\n");
//    }
//
//    // Print Block I/O Media information
//    dprint("  Media ID: %u\n", BlockIo->Media->MediaId);
//    dprint("  Removable Media: %a\n", BlockIo->Media->RemovableMedia ? "TRUE" : "FALSE");
//    dprint("  Media Present: %a\n", BlockIo->Media->MediaPresent ? "TRUE" : "FALSE");
//    dprint("  Logical Prt: %a\n", BlockIo->Media->LogicalPrt ? "TRUE" : "FALSE");
//    dprint("  Read Only: %a\n", BlockIo->Media->ReadOnly ? "TRUE" : "FALSE");
//    dprint("  Block Size: %u bytes\n", BlockIo->Media->BlockSize);
//    dprint("  Last Block LBA: 0x%Lx\n", BlockIo->Media->LastBlock);
//    dprint("  Total Size: %Lu bytes\n", MultU64x32(BlockIo->Media->LastBlock + 1, BlockIo->Media->BlockSize));
//
//
//    //
//    // Example: Reading the first block (LBA 0) of the current device/Prt
//    //
//    if (BlockIo->Media->MediaPresent && !BlockIo->Media->ReadOnly && BlockIo->Media->BlockSize > 0) {
//        // Allocate a buffer for one block of data
//        ReadBuffer = AllocatePool(BlockIo->Media->BlockSize);
//        if (ReadBuffer == NULL) {
//            dprint("  ERROR: Failed to allocate buffer for block read.\n");
//            // Continue to next handle or return
//        } else {
//            dprint("  Attempting to read LBA 0 (size %u bytes)...\n", BlockIo->Media->BlockSize);
//            Status = BlockIo->ReadBlocks(
//                                  BlockIo,
//                                  BlockIo->Media->MediaId,
//                                  0, // LBA 0
//                                  BlockIo->Media->BlockSize,
//                                  ReadBuffer
//                                  );
//            if (EFI_ERROR(Status)) {
//                dprint("  ERROR: Failed to read LBA 0: %r\n", Status);
//            } else {
//                dprint("  Successfully read LBA 0.\n");
//                // You can now inspect 'ReadBuffer' to see the raw data.
//                // For example, if it's a disk, LBA 0 might contain MBR or GPT header.
//                // dprint("  First 16 bytes of LBA 0: ");
//                // for (UINTN i = 0; i < 16; i++) {
//                //   dprint("%02x ", ((UINT8*)ReadBuffer)[i]);
//                // }
//                // dprint("\n");
//            }
//            FreePool(ReadBuffer); // Always free the buffer
//            ReadBuffer = NULL;
//        }
//    } else {
//        dprint("  Cannot read from this device (media not present, read-only, or block size is 0).\n");
//    }
//  }
//
//  if (HandleBuffer != NULL) {
//    FreePool(HandleBuffer);
//  }
//
//  return EFI_SUCCESS;
//}

VOID  SBCGetBlkIoHandleParse(VOID)
{
  EFI_HANDLE    *HandleList;
  EFI_HANDLE    *HandleListWalker;
  CHAR16        *Name;
  CONST CHAR16  *Lang = L"EN";
  CHAR8         *Language;
  CHAR8         DeviceName[512];

  HandleList = GetHandleListByProtocol(&gEfiBlockIoProtocolGuid);
  if(HandleList == NULL) {
    dprint("GetHandleListByProtocol Nill \n" );
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



EFI_STATUS SBCGetDirFile(VOID)
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
    dprint("Failed to locate Simple File System Protocol: %r\n", Status);
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
      dprint("Failed to get Simple File System Protocol from handle: %r\n", Status);
      continue;
    }

    // Open the root volume
    Status = SimpleFileSystem->OpenVolume (
                                 SimpleFileSystem,
                                 &Root
                                 );
    if (EFI_ERROR (Status)) {
      dprint("Failed to open file system volume: %r\n", Status);
      continue;
    }

    dprint("\n--- Listing contents of a file system ---\n");

    // Allocate a buffer for file info (adjust size as needed)
    FileInfoSize = sizeof(EFI_FILE_INFO) + 256; // Max path length + struct size
    Status = gBS->AllocatePool (
                    EfiBootServicesData,
                    FileInfoSize,
                    (VOID **)&FileInfo
                    );
    if (EFI_ERROR (Status)) {
      dprint("Failed to allocate memory for file info: %r\n", Status);
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
      dprint("%s %s\n",
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

SBCStatus SBC_LoadSystemSetting(VOID *blkio, VOID *blob)
{
    SBCStatus ret = SBCOK;
    UINTN lba = 0;
    UINT32 ldlen = 0;


    lba = SYS_CONF_START_OFS >> SBC_RAWPRT_DFLT_SHIFT;
    ldlen = ALIGN_VALUE(SYS_SETTING_STORAGE_LEN, 
                        ((EFI_BLOCK_IO_PROTOCOL *)blkio)->Media->BlockSize);

    ((LV_t *)blob)->value = AllocateZeroPool(ldlen);
    SBC_RET_VALIDATE_ERRCODEMSG((((LV_t *)blob)->value != NULL), 
                                SBCNULLP,
                                "Memory Allocate Fail");

    
    ret = SBC_RawPrtReadBlock(
        blkio,
        ((LV_t *)blob)->value,
        &ldlen,
        lba
        );

    SBC_RET_VALIDATE_ERRCODEMSG((ret == SBCOK),
                                ret,
                                "Block IO Load fail");

    ((LV_t *)blob)->length = ldlen;

errdone:
    return ret;
}

SBCStatus SBC_RawAlignedWriteBlockIO(VOID *blk, UINTN off, UINTN sz, CONST VOID *buf)
{
    SBCStatus ret = SBCOK;
    EFI_BLOCK_IO_PROTOCOL *io = (EFI_BLOCK_IO_PROTOCOL *)blk; 
    UINT32 B;
    UINTN total;
    EFI_LBA lba;
    EFI_STATUS retval;
    UINTN cur;
    UINT8 *p;
    UINTN intra;


    EFI_BLOCK_IO_MEDIA *m = io->Media;

    if ( !m || !m->MediaPresent) {
        eprint("EFI NO MEDIA");
        ret = SBCIO;
        goto errdone;
    }

    B = m->BlockSize;
    total =(m->LastBlock + 1ULL) *  (UINT64)B;

    //
    // Check the Block IO device boundary
    //
    if (off > total || off + sz > total) {
        eprint("Invalid Parameter");
        ret = SBCINVPARAM;
        goto errdone;
    }

    cur = off;
    p = (UINT8 *)buf;

    lba = cur / B;
    intra = (UINTN)(cur % B);


    //
    // Head ( Partial Block )
    //
    if (intra) {
        UINT8 *tmp = AllocatePool(B);
        SBC_RET_VALIDATE_ERRCODEMSG((tmp != NULL), SBCNULLP, "Allocation Fail");

        retval=  io->ReadBlocks(io, m->MediaId, lba, B, tmp);
        if (EFI_ERROR(retval)) {
            eprint("Read Block fail (%r)", retval);
            FreePool(tmp);
            return SBCIO;
        }

        UINTN c = MIN(sz, B - intra);
        CopyMem(tmp + intra, p, c);

        retval = io->WriteBlocks(io, m->MediaId, lba, B, tmp);
        FreePool(tmp);
        if (EFI_ERROR(retval)) {
            return SBCIO;
        }

        p += c;
        sz -= c;
        cur += c;
        lba++;
    }

    //
    // Body ( pure write block )
    //
    while (sz >= B) {
        retval = io->WriteBlocks(io, m->MediaId, lba, B, (VOID *)p);
        if (EFI_ERROR(retval)) {
            eprint("Write Blocks fail (%r)", retval);
            return SBCIO;
        }

        p += B;
        sz -= B;
        cur += B;
        lba++;
    }

    //
    // remind blocks
    //
    if (sz) {
        UINT8 *tmp = AllocatePool(B);
        SBC_RET_VALIDATE_ERRCODEMSG((tmp != NULL), SBCNULLP, "Allocation Fail");

        retval = io->ReadBlocks(io, m->MediaId, lba, B, tmp);
        if (EFI_ERROR(retval)) {
            FreePool(tmp);
            return SBCIO;
        }

        CopyMem(tmp, p, sz);
        retval = io->WriteBlocks(io, m->MediaId, lba, B, tmp);
        FreePool(tmp);
        if (EFI_ERROR(retval)) {
            return SBCIO;
        }
    }


    ret = SBCOK;





errdone:

    return ret;

}

SBCStatus SBC_RawAlignedReadBlockIO(VOID *blk, UINTN off, UINTN sz, VOID *buf)
{

    SBCStatus               ret = SBCOK;
    EFI_STATUS              retval = EFI_SUCCESS;
    EFI_BLOCK_IO_PROTOCOL  *io = (EFI_BLOCK_IO_PROTOCOL *)blk;
    UINT32                  B = io->Media->BlockSize;
    EFI_LBA                 lba = off / B;

    UINTN                   o = (UINTN)(off % B);
    UINT8                   *p = NULL;
    UINT8                   *tmp = NULL;

    //dprint("newer Offset : 0x%lx, LBA : %ld, O : %ld, Size : %ld", 
    //       off, lba, o, sz);

    if ( o == 0 && (sz % B) == 0) {
        return io->ReadBlocks(io, io->Media->MediaId, lba, sz, buf);
    }


    // 
    // Unaligned : read-modify-copy
    //
    p = buf;
    tmp = AllocatePool(B);
    SBC_RET_VALIDATE_ERRCODEMSG((tmp != NULL), SBCNULLP, "Out Of Resource");

    // Head

    if (o) {

        //dprint("lba of head : %ld", lba);
        retval = io->ReadBlocks(io, io->Media->MediaId, lba, B ,tmp);
        if (EFI_ERROR(retval)) {
            dprint("%ld LBA read block fail (%r)", lba, retval);
            ret = SBCIO;
            goto errdone;
        }
        UINTN c = MIN(sz, B - o);
        CopyMem(p, tmp + o, c);

        //SBC_mem_print_bin("Head Read Buf", (UINT8 *)p, c);
        p += c;
        sz -= c;
        lba++;

        
    }



    // Body Copy
    while (sz >= B) {

        //dprint("lba of body : %ld", lba);
        retval = io->ReadBlocks(io, io->Media->MediaId, lba, B, p);
        if (EFI_ERROR(retval)) {
            dprint("%ld LBA read block fail (%r)", lba, retval);
            ret = SBCIO;
            goto errdone;
        }

        p += B;
        sz -= B;
        lba++;

        //dprint("size of body : %ld", sz);
    }

    //
    // tail
    //
    if (sz) {
        //dprint("lba of tail : %ld", lba);
        retval = io->ReadBlocks(io, io->Media->MediaId, lba, B, tmp);
        if (EFI_ERROR(retval)) {
            dprint("%ld LBA read block fail (%r)", lba, retval);
            ret = SBCIO;
            goto errdone;
        }
        CopyMem(p, tmp, sz);
        //SBC_mem_print_bin("Tail Read Buf", (UINT8 *)p, sz);
    }

errdone:

    //SBC_mem_print_bin("Read Buf", (UINT8 *)buf, sz);
    if (tmp) {
        FreePool(tmp);
    }
    return ret;

}

SBCStatus SBC_StoreRawPrt(VOID *handle, UINT8 *shared_secret, UINT8 *encbuf, UINTN *wrlen, UINTN wr_ofs)
{
    SBCStatus ret = SBCOK;
    boot_proc_t *p = (boot_proc_t *)handle;
    
    UINT8 iv[SBC_AT_RP_IV_LEN], tag[SBC_AT_RP_TAG_LEN];
    UINT8 enc[SBC_AT_RP_SYS_CONF_MAX_LEN];   
    SBC_AESContext aesctx;
    SBC_AESGcmCtx  ctx;  

    UINT8 *wrtemp = NULL;
    UINTN cpyofs = 0ULL;

    SBC_RngGeneration((UINT8 *)shared_secret, 
                      SYS_OSID_KEY_LEN,
                      SBC_AT_IV_LEN,
                      iv);

    ctx.out.value = enc;
    ctx.out.length = *wrlen;
    ctx.msg.value = encbuf;
    ctx.msg.length = *wrlen;

    aesctx.gcm = &ctx;
    aesctx.algoid= SBC_CIPHER_AES_GCM;

    SBC_AESGcmSetContext((void *)aesctx.gcm,
                         (void *)shared_secret,
                         (void *)iv,
                         (void *)tag);

    ret = SBC_AESGcmEncrypt(&aesctx);
    SBC_RET_VALIDATE_ERRCODEMSG((ret == SBCOK),
                                ret,
                                "SBC Data Encrypt Fail");



    
    wrtemp = AllocatePool(*wrlen + SBC_AT_IV_LEN + SBC_AT_TAG_LEN + 4);
    SBC_RET_VALIDATE_ERRCODEMSG((wrtemp != NULL), SBCNULLP, "Out of Resource");

    CopyMem(&wrtemp[cpyofs], (void *)wrlen, 4);
    cpyofs += 4;

    CopyMem(&wrtemp[cpyofs], enc, *wrlen);
    cpyofs += *wrlen;

    CopyMem(&wrtemp[cpyofs], iv, SBC_AT_RP_IV_LEN);
    cpyofs += SBC_AT_RP_IV_LEN;

    CopyMem(&wrtemp[cpyofs], tag, SBC_AT_RP_TAG_LEN);
    cpyofs += SBC_AT_RP_TAG_LEN;

    ret = SBC_RawAlignedWriteBlockIO(p->blkhnd,
                                     wr_ofs,
                                     cpyofs,
                                     wrtemp);
    SBC_RET_VALIDATE_ERRCODEMSG(!(ret != SBCOK), ret, "Data Write fail in RawPartition");

errdone:

    if (wrtemp) {
        FreePool(wrtemp);
    }

    return ret;
}

SBCStatus SBC_LoadRawPrt(VOID *handle, UINT8 *shared_secret, UINT8 *decbuf, UINTN *rdlen, UINTN rd_ofs)
{
    SBCStatus ret = SBCOK;

    boot_proc_t *p = (boot_proc_t *)handle; 
    UINT8 encbuf[SBC_AT_RP_SYS_CONF_MAX_LEN]  = {0,};
    CHAR16 err_out_key_val[128] = {0, };
    //UINT8 decbuf[SBC_AT_RP_SYS_CONF_MAX_LEN]  = {0,};
    //UINT8 dec_key[SBC_AT_RP_KEY_LEN] = {0,};
    UINTN enclen = 0ULL;
    //UINTN rd_ofs = SYS_CONF_START_OFS + SYS_CONF_SW_LIST_OFS;
    UINT8 iv[SBC_AT_RP_IV_LEN], tag[SBC_AT_RP_TAG_LEN];

    SBC_AESContext aesctx;
    SBC_AESGcmCtx  ctx;


    

//  ret = SBC_DeviceSecuirtyKeyCreate(dec_key);
//  SBC_RET_VALIDATE_ERRCODEMSG((ret == SBCOK), ret, "Protected SW List Cnt read fail");

    ret  = SBC_RawAlignedReadBlockIO(p->blkhnd, 
                                     rd_ofs,
                                     SBC_RAW_PRTHDR_LEN_OFS,
                                     &enclen);
    SBC_RET_VALIDATE_ERRCODEMSG((ret == SBCOK), ret, "Protected SW List Cnt read fail");

    
    

    //
    // Reading encrypted protected software
    //
    rd_ofs += SBC_RAW_PRTHDR_LEN_OFS;
    ret  = SBC_RawAlignedReadBlockIO(p->blkhnd, 
                                 rd_ofs,
                                 enclen,
                                 encbuf);

    SBC_mem_print_bin("enc data =", encbuf, enclen);

    //
    // Reading  iv
    //
    rd_ofs += enclen;
    ret  = SBC_RawAlignedReadBlockIO(p->blkhnd, 
                                 rd_ofs,
                                 SBC_AT_RP_IV_LEN,
                                 iv);

    SBC_mem_print_bin("iv data =", iv, SBC_AT_RP_IV_LEN);

    //
    // Reading tag
    //
    rd_ofs += SBC_AT_RP_IV_LEN;
    ret  = SBC_RawAlignedReadBlockIO(p->blkhnd, 
                                 rd_ofs,
                                 SBC_AT_RP_TAG_LEN,
                                 tag);


    SBC_mem_print_bin("tag data =", tag, SBC_AT_RP_TAG_LEN);
    //( p->bm == BOOT_MODE_UPDATE ) ? shared_secret = ((atp_ident_t *)p->keyinfo)->migid : shared_secret = dec_key;




    //
    // Decrypt the Protected SW 
    //

    ctx.msg.value = (void *)encbuf;
    ctx.out.value = (void *)decbuf;
    ctx.msg.length = ctx.out.length = enclen;

    aesctx.gcm = &ctx;
    aesctx.algoid = SBC_CIPHER_AES_GCM;

    dprint("");
    SBC_AESGcmSetContext((void *)aesctx.gcm, 
                     (void *)shared_secret, 
                     (void *)iv, 
                     (void *)tag);

    dprint("");
    if (SBC_AESGcmDecrypt(&aesctx) != SBCOK) {
        SBC_LogHexToStrChar16(shared_secret, 32, err_out_key_val, sizeof(err_out_key_val)/sizeof(err_out_key_val[0]),  FALSE, 0);
        UnicodeSPrint(mrgmsg,  sizeof mrgmsg, L"SBC_ProtSW_Update Failed to decrypt (%s) \n", err_out_key_val);
        sbc_err_sysprn(SBC_LOG_CMN_PRIO_ERR, 2,
                 L"AT_BOOT",
                 L"SSBL",
                 L"SAT",
                 5,
                 L"Detection",
                 mrgmsg);
        ret = SBCENCFAIL;
        goto errdone;
    }

    dprint("");
    *rdlen = enclen;


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
