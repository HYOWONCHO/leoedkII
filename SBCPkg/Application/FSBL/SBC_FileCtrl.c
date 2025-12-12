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

#include "SBC_Util.h"
#include "SBC_FileCtrl.h"

//static UINT32 _get_rw_blkcnt(UINT32 bytes)
//{
//  UINTN       division;
//  UINTN       quotient;
//
//  //quteint = bytes % SBC_RAWPTR_DFLT_BLK_SZ;
//
//  division =
//
//    return ALIGN_VALUE(bytes, SBC_RAWPRT_DFLT_BLK_SZ);
//
//}

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
    //UINTN       idx = 0;

    SBC_RET_VALIDATE_ERRCODEMSG((f_path != NULL), SBCNULLP, "File Path obj Nill");
    SBC_RET_VALIDATE_ERRCODEMSG((*hndl != NULL), SBCNULLP, "Handle Obj Nill");

    for (UINTN idx = 0; idx < *hndlcnt; idx++) {
        retval = SBC_IsFlieAccess(hndl[idx], f_path);
        if (!EFI_ERROR(retval)) {
            *hndlcnt = idx;  
            ret = SBCOK;
            goto errdone;
        }
    }

    eprint("File not found in %u handles", *hndlcnt);
    *hndlcnt = (UINTN)-1;
    ret = SBCNOTFND;

errdone:
    return ret;

}



//SBCStatus  SBC_GetFileSize(IN CHAR16 *FileName, OUT *FileSize)
//SBCStatus  SBC_GetFileSize(CHAR16 *FileName, UINTN  *FileSize)
//{
//    EFI_STATUS Status;
//
//    EFI_HANDLE *ImageHandle;
//    EFI_SIMPLE_FILE_SYSTEM_PROTOCOL *FileSystem;
//    EFI_FILE_PROTOCOL *Root;
//    EFI_FILE_PROTOCOL *File;
//    UINTN              InfoSize = 0;
//    EFI_FILE_INFO     *FileInfo;
//    UINTN               hndlcnt;
//    UINTN               idx;
//
//
//    hndlcnt = SBC_FindEfiFileSystemProtocol(&ImageHandle);
//    Print(L"Hndl Count :%d \n", hndlcnt);
//    if (hndlcnt <= 0) {
//        //Print(L"File Sys handle find fail : %d \n", hndlcnt);
//        return SBCFAIL;
//        //sbc_err_sysprn()
//    }
//
//    for (idx = 1; idx < hndlcnt; idx++) {
//        Status = SBC_IsFlieAccess(ImageHandle[idx], FileName);
//        if (EFI_ERROR(Status)) {
//            eprint("Is File (%r)", Status);
//            continue;
//        }
//
//        break;
//    }
//
//    if (EFI_ERROR(Status)) {
//        eprint("[%d] %s file   %r", idx, FileName, Status);
//        return SBCFAIL;
//    }
//
//
//    Status = gBS->HandleProtocol(ImageHandle[idx],
//                                   &gEfiSimpleFileSystemProtocolGuid,
//                                   (VOID **)&FileSystem);
//    if(EFI_ERROR(Status)) {
//        DEBUG((DEBUG_ERROR, " %a:%d Locate File Systam fail (%r) \r\n",
//               __FUNCTION__, __LINE__, Status));
//        return SBCFAIL;
//    }
//
//    // Open the root directory of the volume.
//    Status = FileSystem->OpenVolume(FileSystem, &Root);
//        if (EFI_ERROR(Status)) {
//        eprint("Failed to open volume: %r\n", Status);
//        return SBCFAIL;
//    }
//
//    // Open the file using the provided Unicode file name.
//    Status = Root->Open(Root, &File, FileName, EFI_FILE_MODE_READ, 0);
//        if (EFI_ERROR(Status)) {
//        eprint("Failed to open file %s: %r\n", FileName, Status);
//        Root->Close(Root);
//        return SBCFAIL;
//    }
//
//    // Query for the size of buffer needed to hold the file info.
//    Status = File->GetInfo(File, &gEfiFileInfoGuid, &InfoSize, NULL);
//    if (Status != EFI_BUFFER_TOO_SMALL) {
//        eprint("Unexpected status when querying file info size: %r\n", Status);
//        File->Close(File);
//        Root->Close(Root);
//        return SBCFAIL;
//    }
//
//    // Allocate memory for the file info structure.
//    FileInfo = AllocatePool(InfoSize);
//        if (FileInfo == NULL) {
//        File->Close(File);
//        Root->Close(Root);
//        eprint("Allocate memory for the file info structure : EFI_OUT_OF_RESOURCES ");
//        return SBCFAIL;
//    }
//
//    // Retrieve the file info.
//    Status = File->GetInfo(File, &gEfiFileInfoGuid, &InfoSize, FileInfo);
//    if (EFI_ERROR(Status)) {
//        eprint("Failed to retrieve file info: %r\n", Status);
//    } else {
//        *FileSize = FileInfo->FileSize;
//    }
//
//    //dprint("File Size : %d", *FileSize);
//
//    // Clean up allocated memory and open handles.
//    FreePool(FileInfo);
//    File->Close(File);
//    Root->Close(Root);
//    return SBCOK;
//
//}

#if 0
SBCStatus
SBC_GetFileSize(
    IN  CHAR16 *FileName,
    OUT UINTN  *FileSize
)
{
    EFI_STATUS                        Status;
    EFI_SIMPLE_FILE_SYSTEM_PROTOCOL  *SimpleFs;
    EFI_FILE_PROTOCOL                *Root;
    EFI_FILE_PROTOCOL                *File;
    EFI_FILE_INFO                    *FileInfo;
    EFI_HANDLE                       *Handles = NULL;
    UINTN                             HandleCount = 0;
    UINTN                             InfoSize = 0;

    dprint("SBC_GetFileSizeSimple() called");
    dprint("  FileName : %s", FileName);

    //
    // Find all filesystem handles
    //
    Status = gBS->LocateHandleBuffer(
                    ByProtocol,
                    &gEfiSimpleFileSystemProtocolGuid,
                    NULL,
                    &HandleCount,
                    &Handles
                 );

    if (EFI_ERROR(Status)) {
        eprint("  LocateHandleBuffer failed: %r", Status);
        return SBCNOTFND;
    }

    dprint("  Found FS handles: %d", HandleCount);

    //
    // Search each filesystem
    //
    for (UINTN i = 0; i < HandleCount; i++) {

        dprint("  Checking FS Handle[%d] : %p", i, Handles[i]);

        Status = gBS->HandleProtocol(
                        Handles[i],
                        &gEfiSimpleFileSystemProtocolGuid,
                        (VOID**)&SimpleFs
                     );
        if (EFI_ERROR(Status)) {
            eprint("    HandleProtocol failed: %r", Status);
            continue;
        }

        Status = SimpleFs->OpenVolume(SimpleFs, &Root);
        if (EFI_ERROR(Status)) {
            eprint("    OpenVolume failed: %r", Status);
            continue;
        }

        dprint("    OpenVolume OK. Trying to open file...");

        //
        // Try opening the file
        //
        Status = Root->Open(
                        Root,
                        &File,
                        FileName,
                        EFI_FILE_MODE_READ,
                        0
                     );

        if (EFI_ERROR(Status)) {
            eprint("    File not found in this FS: %r", Status);
            continue;
        }

        dprint("    File open OK!");

        //
        // Step 1: Get required FileInfo buffer size
        //
        Status = File->GetInfo(
                        File,
                        &gEfiFileInfoGuid,
                        &InfoSize,
                        NULL
                     );
        if (Status != EFI_BUFFER_TOO_SMALL) {

            eprint("    GetInfo size query failed: %r", Status);

            File->Close(File);
            continue;
        }

        dprint("    FileInfo size needed: %d bytes", InfoSize);

        FileInfo = AllocateZeroPool(InfoSize);
        if (!FileInfo) {
            eprint("    AllocateZeroPool(%d) failed", InfoSize);
            File->Close(File);
            continue;
        }

        //
        // Step 2: Get actual FileInfo
        //
        Status = File->GetInfo(
                        File,
                        &gEfiFileInfoGuid,
                        &InfoSize,
                        FileInfo
                     );

        if (EFI_ERROR(Status)) {
            eprint("    GetInfo failed: %r", Status);

            FreePool(FileInfo);
            File->Close(File);
            continue;
        }

        dprint("    FileInfo loaded.");
        dprint("    File Size: %ld bytes", FileInfo->FileSize);

        *FileSize = FileInfo->FileSize;

        FreePool(FileInfo);
        File->Close(File);
        FreePool(Handles);

        dprint("SBC_GetFileSizeSimple() OK");
        return SBCOK;
    }

    //
    // All FS checked, none had the file
    //
    eprint("SBC_GetFileSizeSimple() FAIL: File '%s' not found.", FileName);

    FreePool(Handles);
    return SBCNOTFND;
}
#endif

//
// FS Handle의 Root 디렉토리 전체 내용 출력
//
STATIC
VOID
SBC_DumpFsHandleContents(
    EFI_SIMPLE_FILE_SYSTEM_PROTOCOL *SimpleFs
)
{
    EFI_STATUS Status;
    EFI_FILE_PROTOCOL *Root;
    EFI_FILE_PROTOCOL *Dir;
    EFI_FILE_INFO *Info;
    UINTN InfoSize;

    //dprint("    ---- Dumping FS Handle Contents ----");

    //
    // Root 열기
    //
    Status = SimpleFs->OpenVolume(SimpleFs, &Root);
    if (EFI_ERROR(Status)) {
        eprint("    OpenVolume() failed: %r", Status);
        return;
    }

    //
    // 현재 디렉토리(".") 열기
    //
    Status = Root->Open(Root, &Dir, L".", EFI_FILE_MODE_READ, 0);
    if (EFI_ERROR(Status)) {
        eprint("    Root open('.') failed: %r", Status);
        return;
    }

    //
    // 디렉토리 읽기
    //
    while (TRUE) {
        InfoSize = 0;

        Status = Dir->GetInfo(
                    Dir,
                    &gEfiFileInfoGuid,
                    &InfoSize,
                    NULL
                 );

        if (Status != EFI_BUFFER_TOO_SMALL)
            break;

        Info = AllocateZeroPool(InfoSize);
        if (!Info)
            break;

        Status = Dir->Read(Dir, &InfoSize, Info);
        if (EFI_ERROR(Status) || InfoSize == 0) {
            FreePool(Info);
            break;
        }

        if (Info->FileName[0] != L'\0') {
            //dprint("      • %s (%ld bytes)", Info->FileName, Info->FileSize);
        }

        FreePool(Info);
    }

    Dir->Close(Dir);

    //dprint("    ---- End Of FS Handle Contents ----");
}


//
// 파일 크기 검색 + FS 전체 내용 출력
//
SBCStatus
SBC_GetFileSize(
    IN  CHAR16 *FileName,
    OUT UINTN  *FileSize
)
{
    EFI_STATUS                        Status;
    EFI_SIMPLE_FILE_SYSTEM_PROTOCOL  *SimpleFs;
    EFI_FILE_PROTOCOL                *Root;
    EFI_FILE_PROTOCOL                *File;
    EFI_FILE_INFO                    *FileInfo;
    EFI_HANDLE                       *Handles = NULL;
    UINTN                             HandleCount = 0;
    UINTN                             InfoSize = 0;

    //dprint("==== SBC_GetFileSizeSimple() called ====");
    //dprint("  Target File : %s", FileName);

    //
    // 1) FS Handle 전체 획득
    //
    Status = gBS->LocateHandleBuffer(
                    ByProtocol,
                    &gEfiSimpleFileSystemProtocolGuid,
                    NULL,
                    &HandleCount,
                    &Handles
                 );

    if (EFI_ERROR(Status)) {
        eprint("  LocateHandleBuffer failed: %r", Status);
        return SBCNOTFND;
    }

    //dprint("  Found FS handles: %d", HandleCount);

    //
    // 2) Handle 순회
    //
    for (UINTN i = 0; i < HandleCount; i++) {

        //dprint("  -> Checking FS Handle[%d]: %p", i, Handles[i]);

        Status = gBS->HandleProtocol(
                        Handles[i],
                        &gEfiSimpleFileSystemProtocolGuid,
                        (VOID**)&SimpleFs
                     );
        if (EFI_ERROR(Status)) {
            eprint("    HandleProtocol failed: %r", Status);
            continue;
        }

        //
        // ✔ 파일 검색 전에 이 FS의 디렉토리 내용을 먼저 보여줌
        //
        SBC_DumpFsHandleContents(SimpleFs);

        //
        // Root 열기
        //
        Status = SimpleFs->OpenVolume(SimpleFs, &Root);
        if (EFI_ERROR(Status)) {
            eprint("    OpenVolume failed: %r", Status);
            continue;
        }

        //
        // 3) 파일 오픈 시도
        //
        //dprint("    Trying to open target file...");

        Status = Root->Open(
                        Root,
                        &File,
                        FileName,
                        EFI_FILE_MODE_READ,
                        0
                     );

        if (EFI_ERROR(Status)) {
            eprint("    File not found in this FS.");
            continue;
        }

        //dprint("    File opened!");

        //
        // 파일 Info 크기 확보
        //
        Status = File->GetInfo(File, &gEfiFileInfoGuid, &InfoSize, NULL);
        if (Status != EFI_BUFFER_TOO_SMALL) {
            eprint("    GetInfo size failed: %r", Status);
            File->Close(File);
            continue;
        }

        FileInfo = AllocateZeroPool(InfoSize);
        if (!FileInfo) {
            eprint("    Out of memory");
            File->Close(File);
            continue;
        }

        //
        // 실제 정보 획득
        //
        Status = File->GetInfo(File, &gEfiFileInfoGuid, &InfoSize, FileInfo);
        if (EFI_ERROR(Status)) {
            eprint("    GetInfo failed: %r", Status);
            FreePool(FileInfo);
            File->Close(File);
            continue;
        }

        if (FileInfo->Attribute & EFI_FILE_DIRECTORY) {
            //dprint("UEFI thinks '%s' is DIRECTORY (XFS driver limitation).", FileName);
        }
        else {
            //dprint("UEFI thinks '%s' is FILES (XFS driver limitation).", FileName);
        }


        *FileSize = FileInfo->FileSize;

        //dprint("File Attribute = 0x%x", FileInfo->Attribute);
        //dprint("File PhysicalSize = %ld", FileInfo->PhysicalSize);
        //dprint("    SUCCESS! FileSize = %ld bytes", *FileSize);

        FreePool(FileInfo);
        File->Close(File);
        FreePool(Handles);

        //dprint("==== SBC_GetFileSizeSimple() OK ====");
        return SBCOK;
    }

    //
    // 파일을 찾지 못함
    //
    eprint("==== SBC_GetFileSizeSimple() FAIL ====");
    FreePool(Handles);
    return SBCNOTFND;
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

  //dprint();

  //TODO
  // out buffer nill check

  // Locate file system
  Status = gBS->HandleProtocol(ImageHandle,
                               &gEfiSimpleFileSystemProtocolGuid,
                               (VOID **)&FileSystem);
  //dprint();
  if(EFI_ERROR(Status)) {
    DEBUG((DEBUG_ERROR, " %a:%d Locate File Systam fail (%r) \r\n",
           __FUNCTION__, __LINE__, Status));
    return Status;
  }

  //dprint();
  // Open the roor directory
  Status = FileSystem->OpenVolume(FileSystem, &RootDir);
  if (EFI_ERROR(Status)) {
        DEBUG((DEBUG_ERROR, " %a:%d OpenVolume File Systam fail (%r) \r\n",
           __FUNCTION__, __LINE__, Status));
    return Status;
  }

  //dprint();
  // Open the file
  Status = RootDir->Open(RootDir, &File, FileNames, EFI_FILE_MODE_READ | EFI_FILE_MODE_WRITE | EFI_FILE_MODE_CREATE, 0);
  if (EFI_ERROR(Status)) {
      DEBUG((DEBUG_ERROR, " %a:%d RootDir->Open fail (%r) \r\n",
     __FUNCTION__, __LINE__, Status));
      //dprint();
      RootDir->Close(RootDir);
    return Status;
  }

  //dprint();
  // Read the file
  Status = File->Write(File, (UINTN *)&out->length, out->value);
  if (EFI_ERROR(Status)) {
      //dprint();
      DEBUG((DEBUG_ERROR, " %a:%d File->Write fail (%r) \r\n",
              __FUNCTION__, __LINE__, Status));
      //Print(L"File Content: %a\n", Buffer);

      File->Close(File);
      RootDir->Close(RootDir);
      return Status;
  }

  //dprint();


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
      //Print(L"File Content: %a\n", Buffer);
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
        //Print(L"gEfiSimpleFileSystemProtocolGuid foud fail (%r) \n", retval);
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
    //Print(L"Read Boot Mode : %s \n", rdbuf);

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
        //Print(L"No Block IO device found ( %d )\n", Status);
        goto errdone;

    }
//  else {
//      //Print(L"Found %d Block IO device \n" , HandleCount);
//  }

    // Verify Block IO protocol binding
    Status = gBS->HandleProtocol(HandleBuffer[0], &gEfiBlockIoProtocolGuid, (VOID **)&BlockIo);
    if (EFI_ERROR(Status)) {
        //Print(L"Failed to bind Block IO Protocol.(%r)\n",Status);
        goto errdone;
    }

    // Debug ReadBlock or WriteBlock
    Status = BlockIo->ReadBlocks(BlockIo, BlockIo->Media->MediaId, 0, sizeof(Buffer), Buffer);
    if (EFI_ERROR(Status)) {
        //Print(L"Block read failed: %r\n", Status);
        goto errdone;
    } else {
        //Print(L"Block read success.\n");
    }


    //Print(L"Block Size: %d\n", BlockIo->Media->BlockSize);
    //Print(L"Last Block: %lld\n", BlockIo->Media->LastBlock);
    //Print(L"Media Present: %s\n", BlockIo->Media->MediaPresent ? L"Yes" : L"No");

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
        //Print(L"Allocate Pool fail \n");
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
        //Print(L"Read Heade Info fail(%r) %r \n", retval, retval);
        ret = SBCIO;
        goto errdone;
    }

    //SBC_mem_print_bin("Read Buf", readbuf, SBC_RPTN_INFO_LEN << 1);
    //CopyMem(rdbuf, readbuf, SBC_RPTN_INFO_LEN << 1);
    
    //SBC_mem_print_bin("Rd Bud", rdbuf, SBC_RPTN_INFO_LEN << 1);
    //Print(L"Read info result %r (Block Size : %d)\n" , retval, blkio->Media->BlockSize);
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

    //Print(L"%a:%d \n",__FUNCTION__, __LINE__);
    SBC_RET_VALIDATE_ERRCODEMSG((blkhnd != NULL), SBCNULLP, "Block IO Handle Nill");
    SBC_RET_VALIDATE_ERRCODEMSG(((rdbuf != NULL) || (rdlen != NULL)), SBCNULLP, "Invalid parameter");
    SBC_RET_VALIDATE_ERRCODEMSG((*rdlen != 0), SBCZEROL, "Invalid parameter");

    blkio  = (EFI_BLOCK_IO_PROTOCOL *)blkhnd;

    

//  blklen = ALIGN_VALUE(*rdlen, blkio->Media->BlockSize);
//  //Print(L"BLK Len : %d \n", blklen);
//  readbuf = AllocateZeroPool(blklen);
//  if (readbuf == NULL) {
//      //Print(L"Allocate Pool fail \n");
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
        //Print(L"Read Heade Info fail(%r) %r \n", retval, retval);
        ret = SBCIO;
        goto errdone;
    }
    //SBC_mem_print_bin("Read Buf", readbuf, *rdlen);
    //CopyMem(rdbuf, readbuf, *rdlen);
    
    //SBC_mem_print_bin("Rd Bud", rdbuf, SBC_RPTN_INFO_LEN << 1);
    //Print(L"Read info result %r (Block Size : %d)\n" , retval, blkio->Media->BlockSize);
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
        //Print(L"Write Block I/O fail : %r", retval);
        ret = SBCIO;
        goto errdone;
    }

errdone:
    return ret;

}


/**
  Read a text file from any available filesystem and convert it to UTF-16.

  @param[in]  FileName     Full UEFI file path (e.g., L"\\EFI\\BOOT\\config.txt")
  @param[out] OutBuffer    Pointer to receive allocated UTF-16 buffer
  @param[out] OutLength    Number of UTF-16 characters (excluding NULL)

  @retval SBCOK   The file was successfully located and read
  @retval SBCNOTFND  The file could not be found or read
**/
SBCStatus SBC_FileReadUnicodeSimple(
    IN  CHAR16    *FileName,
    OUT CHAR16  **OutBuffer,
    OUT UINTN     *OutLength
)
{
    EFI_STATUS                        Status;
    EFI_HANDLE                       *Handles = NULL;
    UINTN                             HandleCount = 0;
    EFI_SIMPLE_FILE_SYSTEM_PROTOCOL  *SimpleFs;
    EFI_FILE_PROTOCOL                *Root;
    EFI_FILE_PROTOCOL                *File;
    EFI_FILE_INFO                    *FileInfo = NULL;
    UINTN                             FileInfoSize = 0;
    UINT8                            *AsciiBuf = NULL;
    CHAR16                          *UniBuf = NULL;

    //dprint("==== SBC_FileReadUnicode() ====");
    //dprint("  Target File : %s", FileName);

    //
    // Locate all available filesystem handles
    //
    Status = gBS->LocateHandleBuffer(
                    ByProtocol,
                    &gEfiSimpleFileSystemProtocolGuid,
                    NULL,
                    &HandleCount,
                    &Handles
                 );
    if (EFI_ERROR(Status)) {
        eprint("  LocateHandleBuffer() failed: %r", Status);
        return SBCNOTFND;
    }

    //dprint("  Found FS handles: %d", HandleCount);

    //
    // Iterate through all filesystem handles
    //
    for (UINTN i = 0; i < HandleCount; i++) {

        //dprint("  -> Trying FS Handle[%d] = %p", i, Handles[i]);

        //
        // Obtain SimpleFileSystem protocol
        //
        Status = gBS->HandleProtocol(
                        Handles[i],
                        &gEfiSimpleFileSystemProtocolGuid,
                        (VOID**)&SimpleFs
                     );
        if (EFI_ERROR(Status)) {
            eprint("     HandleProtocol failed: %r", Status);
            continue;
        }

        //
        // Open root directory
        //
        Status = SimpleFs->OpenVolume(SimpleFs, &Root);
        if (EFI_ERROR(Status)) {
            eprint("     OpenVolume failed: %r", Status);
            continue;
        }

        //
        // Try opening the target file
        //
        Status = Root->Open(
                        Root,
                        &File,
                        FileName,
                        EFI_FILE_MODE_READ,
                        0
                     );
        if (EFI_ERROR(Status)) {
            //dprint("     File not present in this filesystem");
            continue;
        }

        //dprint("     File opened");

        //
        // Get EFI_FILE_INFO size
        //
        Status = File->GetInfo(File, &gEfiFileInfoGuid, &FileInfoSize, NULL);
        if (Status != EFI_BUFFER_TOO_SMALL) {
            eprint("     GetInfo(size) failed: %r", Status);
            File->Close(File);
            continue;
        }

        FileInfo = AllocateZeroPool(FileInfoSize);
        if (!FileInfo) {
            eprint("     Out of memory (FileInfo)");
            File->Close(File);
            continue;
        }

        //
        // Retrieve actual file info
        //
        Status = File->GetInfo(File, &gEfiFileInfoGuid, &FileInfoSize, FileInfo);
        if (EFI_ERROR(Status)) {
            eprint("     GetInfo failed: %r", Status);
            FreePool(FileInfo);
            File->Close(File);
            continue;
        }

        //
        // Reject directories
        //
        if (FileInfo->Attribute & EFI_FILE_DIRECTORY) {
            eprint("     ERROR: '%s' is directory (Attr=0x%x)",
                   FileName, FileInfo->Attribute);
            FreePool(FileInfo);
            File->Close(File);
            continue;
        }

        //dprint("     FileSize = %ld bytes", FileInfo->FileSize);

        //
        // Allocate ASCII buffer and read file content
        //
        AsciiBuf = AllocateZeroPool(FileInfo->FileSize + 1);
        if (!AsciiBuf) {
            eprint("     Out of memory (AsciiBuf)");
            FreePool(FileInfo);
            File->Close(File);
            continue;
        }

        UINTN ReadSize = FileInfo->FileSize;
        Status = File->Read(File, &ReadSize, AsciiBuf);
        if (EFI_ERROR(Status)) {
            eprint("     Read failed: %r", Status);
            FreePool(AsciiBuf);
            FreePool(FileInfo);
            File->Close(File);
            continue;
        }

        //
        // Convert ASCII → UTF-16
        //
        UINTN UniSize = (ReadSize + 1) * sizeof(CHAR16);
        UniBuf = AllocateZeroPool(UniSize);
        if (!UniBuf) {
            eprint("     Out of memory (Unicode buffer)");
            FreePool(AsciiBuf);
            FreePool(FileInfo);
            File->Close(File);
            continue;
        }

        for (UINTN j = 0; j < ReadSize; j++) {
            UniBuf[j] = (CHAR16)AsciiBuf[j];
        }
        UniBuf[ReadSize] = L'\0';

        //
        // Return results
        //
        *OutBuffer = UniBuf;
        *OutLength = ReadSize;

        //dprint("     UTF-16 read OK (%ld chars)", *OutLength);

        FreePool(AsciiBuf);
        FreePool(FileInfo);
        File->Close(File);
        FreePool(Handles);

        //dprint("==== SBC_FileReadUnicode() OK ====");
        return SBCOK;
    }

    //
    // File not found in any filesystem
    //
    eprint("==== SBC_FileReadUnicode() FAIL ====");
    FreePool(Handles);
    return SBCNOTFND;
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

    SBC_RET_VALIDATE_ERRCODEMSG((hblk != NULL), SBCNULLP, "Invalid Parameter");


    Status = gBS->LocateHandleBuffer(
                    ByProtocol,
                    &gEfiBlockIoProtocolGuid,
                    NULL,
                    &NumberOfHandles,
                    &HandleBuffer
        );

    if (EFI_ERROR(Status)) {
        //Print(L"ERROR: Failed to locate BlockIoProtocol handles: %r\n", Status);
        SBC_RET_VALIDATE_ERRCODEMSG((Status != EFI_SUCCESS), SBCFAIL, "ERROR: Failed to locate BlockIoProtocol handles");
    }

    //Print(L"Found %d Block I/O Protocol handles.\n", NumberOfHandles);

    for (int idx = 0; idx < NumberOfHandles; idx++) {

        // Get the Block I/O protocol interfcae!cp
        Status = gBS->HandleProtocol(
                        HandleBuffer[idx],
                        &gEfiBlockIoProtocolGuid,
                        (VOID **)&BlockIo
            );

        if (EFI_ERROR(Status)) {
            //Print(L"RROR: Could not open BlockIoProtsocol %r\n", Status);
            SBC_RET_VALIDATE_ERRCODEMSG((Status != EFI_SUCCESS), SBCFAIL, "ERROR: Could not open BlockIoProtocol");
        }

        //blkiosz = MultU64x32(BlockIo->Media->LastBlock + 1, BlockIo->Media->BlockSize);
        //Print(L"Found %p Block I/O Protocol Address.\n", BlockIo);


        //Print(L"INFO: Found SBC Raw Partiiton %r\n", Status);

        ReadBuffer = AllocatePool(BlockIo->Media->BlockSize);
        if (ReadBuffer == NULL) {
             //Print(L"Buffer allocatino fail \n");
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
            // How do i process in case of error is EFI_NO_MEDIA
//            //Print(L"ERROR: Failed to read LBA 0: %r\n", Status);
//#ifndef _FSBL_TEST_
//            SBC_RET_VALIDATE_ERRCODEMSG((Status != EFI_SUCCESS), SBCFAIL, "ERROR: Could not open BlockIoProtocol");
//            ret = SBCFAIL;
//            goto errdone;
//#else
//            continue;
//#endif
              continue;
        }

        //SBC_mem_print_bin("Read Block", (UINT8 *)ReadBuffer, SBC_MAGIC_LEN);
        //CopyMem((void *)&magicid, (VOID *)&((UINT8 *)ReadBuffer)[0],SBC_MAGIC_LEN);
        CopyMem((void *)hdr, (VOID *)&((UINT8 *)ReadBuffer)[0], sizeof(rawprt_hdr_t));


        //SBC_mem_print_bin("Header buf", (UINT8 *)hdr, 16);

        FreePool(ReadBuffer);      

        //((rawprt_hdr_t *)hdr)->magicid  = SBC_SWAP_ENDIAN_32(((rawprt_hdr_t *)hdr)->magicid);
        //Print(L"%d Magic ID : 0x%x \n", idx, ((rawprt_hdr_t *)hdr)->magicid);

        
        
        if (((rawprt_hdr_t *)hdr)->magicid != SBC_RAWPRT_MAGIC_ID) {
            continue;
        }

        *hblk = (VOID *)BlockIo;
        //Print(L"Found %p Block I/O Protocol Address Magci ID : 0x%x.\n", BlockIo, ((rawprt_hdr_t *)hdr)->magicid );
        //Print(L"0x%p SBC Raw Buffer MagicID found !!! \n", *hblk);


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
//  //Print(L"Enumerating block devices...\n");
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
//    //Print(L"ERROR: Failed to locate BlockIoProtocol handles: %r\n", Status);
//    return Status;
//  }
//
//  //Print(L"Found %d Block I/O Protocol handles.\n", NumberOfHandles);
//
//  // (Optional) Locate DevicePathToTextProtocol for //Printing
//  gBS->LocateProtocol (&gEfiDevicePathToTextProtocolGuid, NULL, (VOID **)&DevicePathToText);
//
//  //
//  // 2. Iterate through each handle and get Block IO information.
//  //
//  for (Index = 0; Index < NumberOfHandles; Index++) {
//    //Print(L"\n--- Handle %d ---\n", Index);
//
//    // Get the Block I/O Protocol interface
//    Status = gBS->HandleProtocol (
//                    HandleBuffer[Index],
//                    &gEfiBlockIoProtocolGuid,
//                    (VOID **)&BlockIo
//                    );
//    if (EFI_ERROR (Status)) {
//      //Print(L"  ERROR: Could not open BlockIoProtocol: %r\n", Status);
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
//      //Print(L"  WARNING: No Device Path Protocol for this handle: %r\n", Status);
//      DevicePath = NULL; // Ensure it's NULL if not found
//    }
//
//    // //Print device path string (if protocol available)
//    if (DevicePath != NULL && DevicePathToText != NULL) {
//      DevicePathStr = DevicePathToText->ConvertDevicePathToText (DevicePath, FALSE, FALSE);
//      if (DevicePathStr != NULL) {
//        //Print(L"  Device Path: %s\n", DevicePathStr);
//        FreePool(DevicePathStr);
//        DevicePathStr = NULL; // Reset for next iteration
//      }
//    } else if (DevicePath != NULL) {
//      //Print(L"  Device Path present, but DevicePathToTextProtocol not found.\n");
//    }
//
//    // //Print Block I/O Media information
//    //Print(L"  Media ID: %u\n", BlockIo->Media->MediaId);
//    //Print(L"  Removable Media: %a\n", BlockIo->Media->RemovableMedia ? "TRUE" : "FALSE");
//    //Print(L"  Media Present: %a\n", BlockIo->Media->MediaPresent ? "TRUE" : "FALSE");
//    //Print(L"  Logical Prt: %a\n", BlockIo->Media->LogicalPrt ? "TRUE" : "FALSE");
//    //Print(L"  Read Only: %a\n", BlockIo->Media->ReadOnly ? "TRUE" : "FALSE");
//    //Print(L"  Block Size: %u bytes\n", BlockIo->Media->BlockSize);
//    //Print(L"  Last Block LBA: 0x%Lx\n", BlockIo->Media->LastBlock);
//    //Print(L"  Total Size: %Lu bytes\n", MultU64x32(BlockIo->Media->LastBlock + 1, BlockIo->Media->BlockSize));
//
//
//    //
//    // Example: Reading the first block (LBA 0) of the current device/Prt
//    //
//    if (BlockIo->Media->MediaPresent && !BlockIo->Media->ReadOnly && BlockIo->Media->BlockSize > 0) {
//        // Allocate a buffer for one block of data
//        ReadBuffer = AllocatePool(BlockIo->Media->BlockSize);
//        if (ReadBuffer == NULL) {
//            //Print(L"  ERROR: Failed to allocate buffer for block read.\n");
//            // Continue to next handle or return
//        } else {
//            //Print(L"  Attempting to read LBA 0 (size %u bytes)...\n", BlockIo->Media->BlockSize);
//            Status = BlockIo->ReadBlocks(
//                                  BlockIo,
//                                  BlockIo->Media->MediaId,
//                                  0, // LBA 0
//                                  BlockIo->Media->BlockSize,
//                                  ReadBuffer
//                                  );
//            if (EFI_ERROR(Status)) {
//                //Print(L"  ERROR: Failed to read LBA 0: %r\n", Status);
//            } else {
//                //Print(L"  Successfully read LBA 0.\n");
//                // You can now inspect 'ReadBuffer' to see the raw data.
//                // For example, if it's a disk, LBA 0 might contain MBR or GPT header.
//                // //Print(L"  First 16 bytes of LBA 0: ");
//                // for (UINTN i = 0; i < 16; i++) {
//                //   //Print(L"%02x ", ((UINT8*)ReadBuffer)[i]);
//                // }
//                // //Print(L"\n");
//            }
//            FreePool(ReadBuffer); // Always free the buffer
//            ReadBuffer = NULL;
//        }
//    } else {
//        //Print(L"  Cannot read from this device (media not present, read-only, or block size is 0).\n");
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
    //Print(L"GetHandleListByProtocol Nill \n" );
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
    //Print(L"Failed to locate Simple File System Protocol: %r\n", Status);
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
      //Print(L"Failed to get Simple File System Protocol from handle: %r\n", Status);
      continue;
    }

    // Open the root volume
    Status = SimpleFileSystem->OpenVolume (
                                 SimpleFileSystem,
                                 &Root
                                 );
    if (EFI_ERROR (Status)) {
      //Print(L"Failed to open file system volume: %r\n", Status);
      continue;
    }

    //Print(L"\n--- Listing contents of a file system ---\n");

    // Allocate a buffer for file info (adjust size as needed)
    FileInfoSize = sizeof(EFI_FILE_INFO) + 256; // Max path length + struct size
    Status = gBS->AllocatePool (
                    EfiBootServicesData,
                    FileInfoSize,
                    (VOID **)&FileInfo
                    );
    if (EFI_ERROR (Status)) {
      //Print(L"Failed to allocate memory for file info: %r\n", Status);
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

       //Print file/directory name and attributes
      //Print(L"%s %s\n",
      //      (FileInfo->Attribute & EFI_FILE_DIRECTORY) ? L"<DIR>" : L"     ",
      //      FileInfo->FileName
      //     );
    }

    gBS->FreePool (FileInfo);
    Root->Close(Root); // Close the root directory handle
  }

  gBS->FreePool (HandleBuffer);
  return EFI_SUCCESS;

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
    if (EFI_ERROR(retval)) {
        sbc_err_sysprn(SBC_LOG_CMN_PRIO_NOTICE, 2, 
                SYS_LOG_HOST_BOOT, 
                SYS_LOG_APP_NAME, 
                SYS_LOG_CSC_NAME, 
                8, 
                L"Detectrion ", 
                L"SBC_SP_RAWPRT Failed to the Raw-partition read");
    }
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
            dprint("(Offset : %lx, %ld LBA read block fail (%r)", off, lba, retval);
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
            dprint("(Offset : %lx, %ld LBA read block fail (%r)", off, lba, retval);
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
            dprint("(Offset : %lx, %ld LBA read block fail (%r)", off, lba, retval);
            ret = SBCIO;
            goto errdone;
        }
        CopyMem(p, tmp, sz);
        //SBC_mem_print_bin("Tail Read Buf", (UINT8 *)p, sz);
    }

errdone:

    if (EFI_ERROR(retval)) {
        sbc_err_sysprn(SBC_LOG_CMN_PRIO_NOTICE, 2, 
                SYS_LOG_HOST_BOOT, 
                SYS_LOG_APP_NAME, 
                SYS_LOG_CSC_NAME, 
                8, 
                L"Detectrion ", 
                L"SBC_SP_RAWPRT Failed to the Raw-partition read");
    }
    //SBC_mem_print_bin("Read Buf", (UINT8 *)buf, sz);
    if (tmp) {
        FreePool(tmp);
    }
    return ret;

}


#define FILE_CHUNK_SZ   (1024 * 1024) // 파일 읽기 청크 (1MB)

/**
 * @brief Write arbitrary bytes into a block device with read-modify-write for partial blocks.
 *
 * @param[in]  Blk       Block I/O protocol
 * @param[in]  Ofs       Device byte offset to start writing
 * @param[in]  Buf       Data to write
 * @param[in]  Len       Number of bytes to write
 * @return EFI_SUCCESS on success
 */
EFI_STATUS SBC_BlkWriteArbitrary(IN EFI_BLOCK_IO_PROTOCOL *Blk,
                  IN UINT64 Ofs,
                  IN CONST VOID *Buf,
                  IN UINTN Len)
{
    if (!Blk || !Buf || Len == 0) return EFI_INVALID_PARAMETER;

    EFI_BLOCK_IO_MEDIA *m = Blk->Media;
    if (!m || !m->MediaPresent) return EFI_NO_MEDIA;

    UINT32 B = m->BlockSize;
    UINT64 totalBytes = (m->LastBlock + 1ULL) * (UINT64)B;
    if (Ofs > totalBytes || Ofs + Len > totalBytes) return EFI_INVALID_PARAMETER;

    EFI_STATUS Status = EFI_SUCCESS;

    UINT64 cur = Ofs;
    const UINT8 *p = (const UINT8*)Buf;
    UINTN remain = Len;

    // 1) 선두 partial block 처리
    UINTN intra = (UINTN)(cur % B);
    if (intra != 0) {
        UINT64 lba = cur / B;
        UINT8 *blkbuf = AllocatePool(B);
        if (!blkbuf) return EFI_OUT_OF_RESOURCES;

        Status = Blk->ReadBlocks(Blk, m->MediaId, lba, B, blkbuf);
        if (EFI_ERROR(Status)) { FreePool(blkbuf); return Status; }

        UINTN can = (UINTN)B - intra;
        if (can > remain) can = remain;

        CopyMem(blkbuf + intra, p, can);
        Status = Blk->WriteBlocks(Blk, m->MediaId, lba, B, blkbuf);
        FreePool(blkbuf);
        if (EFI_ERROR(Status)) return Status;

        cur += can;
        p   += can;
        remain -= can;
    }

    // 2) 중간 full blocks
    while (remain >= B) {
        UINT64 lba = cur / B;
        // 최대한 여러 블록을 한 번에 쓰고 싶으면 여기서 배수로 합칠 수 있음
        UINTN full = (remain / B) * B;
        // 너무 크게 잡지 않도록 상한 (예: 4MB) — 필요시 조절
        if (full > (4 * 1024 * 1024)) full = 4 * 1024 * 1024;

        Status = Blk->WriteBlocks(Blk, m->MediaId, lba, full, (VOID*)p);
        if (EFI_ERROR(Status)) return Status;

        cur += full;
        p   += full;
        remain -= full;
    }

    // 3) 말미 partial block 처리
    if (remain > 0) {
        UINT64 lba = cur / B;
        UINT8 *blkbuf = AllocatePool(B);
        if (!blkbuf) return EFI_OUT_OF_RESOURCES;

        Status = Blk->ReadBlocks(Blk, m->MediaId, lba, B, blkbuf);
        if (EFI_ERROR(Status)) { FreePool(blkbuf); return Status; }

        CopyMem(blkbuf, p, remain);
        Status = Blk->WriteBlocks(Blk, m->MediaId, lba, B, blkbuf);
        FreePool(blkbuf);
        if (EFI_ERROR(Status)) return Status;

        cur += remain;
        p   += remain;
        remain = 0;
    }

    // 캐시 일관성 확보 (일부 펌웨어에서 효과 없음/무시될 수 있음)
    if (Blk->FlushBlocks) {
        Blk->FlushBlocks(Blk);
    }

    return EFI_SUCCESS;
}

EFI_STATUS
SBC_BlkReadArbitrary(
    IN  EFI_BLOCK_IO_PROTOCOL *Blk,
    IN  UINT64                 ByteOffset,
    OUT VOID                  *Buffer,
    IN  UINTN                  Length
)
{
    if (!Blk || !Buffer || Length == 0)
        return EFI_INVALID_PARAMETER;

    EFI_STATUS Status;
    EFI_BLOCK_IO_MEDIA *m = Blk->Media;

    if (!m || !m->MediaPresent)
        return EFI_NO_MEDIA;

    UINT32 BlockSize = m->BlockSize;
    UINT64 LastBlock = m->LastBlock;

    UINT64 TotalBytes = (LastBlock + 1ULL) * (UINT64)BlockSize;

    //
    // 범위 체크
    //
    if (ByteOffset >= TotalBytes ||
        ByteOffset + Length > TotalBytes)
        return EFI_INVALID_PARAMETER;

    //
    // ByteOffset → LBA 변환
    //
    UINT64 StartLba    = ByteOffset / BlockSize;
    UINTN  InnerOffset = (UINTN)(ByteOffset % BlockSize);

    UINTN EndOffset = InnerOffset + Length;
    UINTN BlockCount = (EndOffset + BlockSize - 1) / BlockSize;
    UINTN ReadSize   = BlockCount * BlockSize;

    //
    // aligned temp buffer 준비
    //
    EFI_PHYSICAL_ADDRESS Phys;
    Status = gBS->AllocatePages(
                    AllocateAnyPages,
                    EfiBootServicesData,
                    EFI_SIZE_TO_PAGES(ReadSize),
                    &Phys
                );
    if (EFI_ERROR(Status))
        return Status;

    VOID *Tmp = (VOID*)(UINTN)Phys;

    //
    // Block 단위 읽기
    //
    Status = Blk->ReadBlocks(
                    Blk,
                    m->MediaId,
                    StartLba,
                    ReadSize,
                    Tmp
                );

    if (EFI_ERROR(Status)) {
        gBS->FreePages(Phys, EFI_SIZE_TO_PAGES(ReadSize));
        return Status;
    }

    //
    // 사용자 버퍼로 필요한 부분만 복사
    //
    CopyMem(Buffer, (UINT8*)Tmp + InnerOffset, Length);

    gBS->FreePages(Phys, EFI_SIZE_TO_PAGES(ReadSize));

    return EFI_SUCCESS;
}


EFI_STATUS SBC_CopyBlockDeviceToFile(
    IN VOID   *_Blk,
    IN UINT64  ByteOffset,
    IN UINT64  DataBytes,
    IN CHAR16 *DstPath,
    OUT UINT64 *BytesRead OPTIONAL
)
{
    if (BytesRead) *BytesRead = 0;
    if (!_Blk || !DstPath) return EFI_INVALID_PARAMETER;

    EFI_STATUS Status;
    EFI_BLOCK_IO_PROTOCOL *Blk = (EFI_BLOCK_IO_PROTOCOL*)_Blk;
    EFI_SIMPLE_FILE_SYSTEM_PROTOCOL *Fs = NULL;
    EFI_FILE_PROTOCOL *Root = NULL, *OutFile = NULL;

    // Block I/O Media
    EFI_BLOCK_IO_MEDIA *m = Blk->Media;
    if (!m || !m->MediaPresent)
        return EFI_NO_MEDIA;

    UINT32 BlockSize = m->BlockSize;
    UINT64 TotalBytes = (m->LastBlock + 1ULL) * (UINT64)BlockSize;

    //
    // 범위 체크
    //
    if (ByteOffset > TotalBytes || ByteOffset + DataBytes > TotalBytes) {
        return EFI_INVALID_PARAMETER;
    }

    //
    // 1) Filesystem 찾기
    //
    Status = gBS->LocateProtocol(&gEfiSimpleFileSystemProtocolGuid, NULL, (VOID**)&Fs);
    if (EFI_ERROR(Status)) return Status;

    Status = Fs->OpenVolume(Fs, &Root);
    if (EFI_ERROR(Status)) return Status;

    //
    // 2) 출력 파일 생성
    //
    Status = Root->Open(
                    Root,
                    &OutFile,
                    DstPath,
                    EFI_FILE_MODE_READ | EFI_FILE_MODE_WRITE | EFI_FILE_MODE_CREATE,
                    0
                );
    if (EFI_ERROR(Status)) {
        Root->Close(Root);
        return Status;
    }

    //
    // 3) CHUNK 로 Block Device 읽기
    //
    UINT64 remaining = DataBytes;
    UINT64 offset = ByteOffset;
    UINT64 readTotal = 0;

    UINT8 *buf = AllocatePool(FILE_CHUNK_SZ);
    if (!buf) {
        OutFile->Close(OutFile);
        Root->Close(Root);
        return EFI_OUT_OF_RESOURCES;
    }

    while (remaining > 0) {

        UINTN chunk = (remaining > FILE_CHUNK_SZ) ? FILE_CHUNK_SZ : (UINTN)remaining;

        //
        // Block Device → Read
        //
        Status = SBC_BlkReadArbitrary(Blk, offset, buf, chunk);
        if (EFI_ERROR(Status)) {
            break;
        }

        //
        // 파일에 Write
        //
        UINTN wr = chunk;
        Status = OutFile->Write(OutFile, &wr, buf);
        if (EFI_ERROR(Status)) {
            break;
        }

        offset     += chunk;
        remaining  -= chunk;
        readTotal  += chunk;

        // 진행률 표시
        UINTN pct = (UINTN)((readTotal * 100) / DataBytes);
        Print(L"\rReading from Block: %3u%%", pct);
    }

    Print(L"\rReading from Block: 100%%\n");

    if (buf) FreePool(buf);

    OutFile->Close(OutFile);
    Root->Close(Root);

    if (BytesRead) *BytesRead = readTotal;

    return Status;
}


SBCStatus SBC_DeleteFile (
    IN CHAR16 *FilePath
    )
{
    if (FilePath == NULL)
        return SBCNULLP;

    EFI_STATUS Status;
    EFI_SIMPLE_FILE_SYSTEM_PROTOCOL *Fs = NULL;
    EFI_FILE_PROTOCOL *Root = NULL;
    EFI_FILE_PROTOCOL *File = NULL;

    //
    // Locate FS protocol
    //
    Status = gBS->LocateProtocol(
                    &gEfiSimpleFileSystemProtocolGuid,
                    NULL,
                    (VOID**)&Fs
                );
    if (EFI_ERROR(Status))
        return SBCFAIL;

    //
    // Open root
    //
    Status = Fs->OpenVolume(Fs, &Root);
    if (EFI_ERROR(Status))
        return SBCFAIL;

    //
    // Try open target file
    //
    Status = Root->Open(
                    Root,
                    &File,
                    FilePath,
                    EFI_FILE_MODE_READ | EFI_FILE_MODE_WRITE,
                    0
                );

    if (Status == EFI_NOT_FOUND) {
        Root->Close(Root);
        return SBCNOTFND;
    }

    if (EFI_ERROR(Status)) {
        Root->Close(Root);
        return SBCFAIL;
    }

    //
    // Delete file
    //
    Status = File->Delete(File);

    //
    // Close root directory
    //
    Root->Close(Root);

    //
    // 🔥 Workaround: Re-open Root to prevent Write-Protected issues
    //
    {
        EFI_FILE_PROTOCOL *TmpRoot = NULL;
        EFI_STATUS St2 = Fs->OpenVolume(Fs, &TmpRoot);
        if (!EFI_ERROR(St2)) {
            TmpRoot->Close(TmpRoot); // Just open + close for cleanup
        }
    }

    if (EFI_ERROR(Status))
        return SBCFAIL;

    return SBCOK;
}

/**
 * @brief Copy a file into a block device at given byte offset.
 */
EFI_STATUS SBC_CopyFileToBlockDevice(IN CHAR16 *SrcPath,
                      IN VOID *_Blk,
                      IN UINT64 ByteOffset,
                      OUT UINT64 *BytesWritten OPTIONAL)
{
    if (BytesWritten) *BytesWritten = 0;

    if (!SrcPath || !_Blk) return EFI_INVALID_PARAMETER;
    EFI_STATUS Status;
    EFI_SIMPLE_FILE_SYSTEM_PROTOCOL *Fs = NULL;
    EFI_FILE_PROTOCOL *Root = NULL, *InFile = NULL;
    EFI_FILE_INFO *Info = NULL;
    UINTN InfoSz = 0;
    EFI_BLOCK_IO_PROTOCOL *Blk = (EFI_BLOCK_IO_PROTOCOL *)_Blk;

    if (BytesWritten) *BytesWritten = 0;

    if (!SrcPath || !_Blk) {
         dprint("");
        return EFI_INVALID_PARAMETER;
    }

    // 1) 소스 파일 열기
    Status = gBS->LocateProtocol(&gEfiSimpleFileSystemProtocolGuid, NULL, (VOID**)&Fs);
    if (EFI_ERROR(Status)) {
        dprint("");
        return Status;
    }

    Status = Fs->OpenVolume(Fs, &Root);
    if (EFI_ERROR(Status)) {
        dprint("");
        return Status;
    }


    Status = Root->Open(Root, &InFile, SrcPath, EFI_FILE_MODE_READ, 0);
    if (EFI_ERROR(Status)) {
        dprint("");
         Root->Close(Root); 
         return Status; 
    }

    // 2) 파일 크기 얻기
    Status = InFile->GetInfo(InFile, &gEfiFileInfoGuid, &InfoSz, NULL);

    if (Status == EFI_BUFFER_TOO_SMALL) {
        dprint("%s info size %ld ", SrcPath, InfoSz);
        Info = AllocateZeroPool(InfoSz);
        dprint("");
        Status = InFile->GetInfo(InFile, &gEfiFileInfoGuid, &InfoSz, Info);
        dprint("");
    }
    if (EFI_ERROR(Status)) {
        dprint("");
        InFile->Close(InFile);
        Root->Close(Root);
        if (Info) FreePool(Info);
        return Status;
    }

    UINT64 fileSize = Info->FileSize;
    dprint("%s filee size %ld ", SrcPath, fileSize);
    FreePool(Info);

    // 3) 디바이스 경계 체크
    EFI_BLOCK_IO_MEDIA *m = Blk->Media;
    if (!m || !m->MediaPresent) {
        dprint("");
        InFile->Close(InFile);
        Root->Close(Root);
        return EFI_NO_MEDIA;
    }
    UINT32 B = m->BlockSize;
    UINT64 totalBytes = (m->LastBlock + 1ULL) * (UINT64)B;

    if (ByteOffset > totalBytes || ByteOffset + fileSize > totalBytes) {
        dprint("");
        InFile->Close(InFile);
        Root->Close(Root);
        return EFI_VOLUME_FULL; // or EFI_INVALID_PARAMETER
    }

    // 4) 파일을 청크로 읽어서 블록디바이스에 쓰기
    UINT8 *buf = AllocatePool(FILE_CHUNK_SZ);
    if (!buf) {
        dprint("");
        InFile->Close(InFile);
        Root->Close(Root);
        return EFI_OUT_OF_RESOURCES;
    }

    UINT64 written = 0;
    while (TRUE) {
        UINTN rd = FILE_CHUNK_SZ;
        //dprint("");
        Status = InFile->Read(InFile, &rd, buf);
        //dprint("");
        if (EFI_ERROR(Status)) {
            dprint("");
            break;
        }
        if (rd == 0) {
            //dprint("");
            break; // EOF
        }

        Status = SBC_BlkWriteArbitrary(Blk, ByteOffset + written, buf, rd);
        if (EFI_ERROR(Status)) {
            dprint("");
             break;
        }

        written += rd;

        // 진행률 간단 표시
        UINTN pct = (UINTN)((written * 100) / fileSize);
        Print(L"\rWriting to Block: %3u%%", pct);
    }
    Print(L"\rWriting to Block: 100%%\n");

    if (buf) FreePool(buf);
    InFile->Close(InFile);
    Root->Close(Root);

    if (BytesWritten) *BytesWritten = written;
    return Status;
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




