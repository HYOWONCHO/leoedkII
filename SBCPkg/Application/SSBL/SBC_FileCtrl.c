/********************************************************************************
 * Copyright (C) 2024 by Security Platform Inc.                                 *
 * This file is part of the SBC Project.                                        *
 *                                                                              *
 * This software contains confidential and proprietary information of           *
 * Security Platform Inc. Unauthorized reproduction, distribution, or           *
 * disclosure of this software, in whole or in part, is strictly prohibited.    *
 ********************************************************************************/

/**
 * @file SBC_FileCtrl.c
 * @brief Data is write and read from/to the specified File or
 *        in SBC Raw-partition
 *
 * @author LEON
 * @version 1.0
 * @date 2025-10-31
 *
 * @copyright (c) 2025 Security Platform Inc. All rights
 *            reserved.
 *
 * @details
 */

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
//#include "SBC_AntiTampering.h"
#include "SBC_Config.h"



SBCStatus  SBC_FindFileBufHndl(UINT16 *f_path, UINTN *hndlcnt, VOID **hndl)
{
    
    SBCStatus   ret = SBCOK;
    if (f_path == NULL) {
        SBC_RET_VALIDATE_ERRCODEMSG(FALSE, SBCNULLP, "File Path obj Nill");
    }

    if (hndl == NULL || *hndl == NULL) {
        SBC_RET_VALIDATE_ERRCODEMSG(FALSE, SBCNULLP, "Handle Obj Nill");
    }

    for (UINTN idx = 0; idx < *hndlcnt; idx++) {
        if (!EFI_ERROR(SBC_IsFlieAccess(hndl[idx], f_path))) {
            *hndlcnt = idx;
            return SBCOK;
        }
    }

    return SBCNOTFND;

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
SBCStatus SBC_GetFileSize(
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
            //eprint("    File not found in this FS.");
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
        sbc_err_sysprn(SBC_LOG_CMN_PRIO_NOTICE, 2, 
                SYS_LOG_HOST_BOOT, 
                SYS_LOG_APP_NAME, 
                SYS_LOG_CSC_NAME, 
                8, 
                L"Detectrion ", 
                L"SBC_SP_RAWPRT Failed to the Raw-partition read");
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

    SBC_RET_VALIDATE_ERRCODEMSG(((blkio != NULL) || (wrbuf != NULL)), SBCNULLP, "Invalid Parameter");
    // before change SBC_LogPrint
    //SBC_RET_VALIDATE_ERRCODEMSG(((p != NULL) || (wrbuf != NULL)), SBCNULLP, "Invalid Parameter");
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
        sbc_err_sysprn(SBC_LOG_CMN_PRIO_NOTICE, 2, 
                SYS_LOG_HOST_BOOT, 
                SYS_LOG_APP_NAME, 
                SYS_LOG_CSC_NAME, 
                8, 
                L"Detectrion ", 
                L"SBC_SP_RAWPRT Failed to the Raw-partition write");
        ret = SBCIO;
        goto errdone;
    }

errdone:
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

//  dprint("newer Offset : 0x%lx, LBA : %ld, O : %ld, Size : %ld",
//         off, lba, o, sz);

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

        //dprint("lba of head : %ld (0xlx)", lba, lba*512);
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

        //dprint("lba of body : %ld (0xlx)", lba, lba*512);
        retval = io->ReadBlocks(io, io->Media->MediaId, lba, B, p);
        if (EFI_ERROR(retval)) {
            dprint("(Offset : %lx, %ld LBA read block fail (%r)", off, lba, retval);
            ret = SBCIO;
            goto errdone;
        }

         //SBC_mem_print_bin("Body Read Buf", (UINT8 *)p, B);

        p += B;
        sz -= B;
        lba++;

        

       
    }

    //dprint("size of body : %ld", sz);

    //
    // tail
    //
    if (sz) {
        //dprint("lba of tail : %ld (0xlx)", lba, lba*512);
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


SBCStatus SBC_ProtSwLoadRawPrt(VOID *handle, 
                         UINT8 *shared_secret, 
                         UINT8 *decbuf, 
                         UINTN *rdlen, 
                         UINTN rd_ofs)
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

    //SBC_mem_print_bin("enc data =", encbuf, enclen);

    //
    // Reading  iv
    //
    rd_ofs += enclen;
    ret  = SBC_RawAlignedReadBlockIO(p->blkhnd, 
                                 rd_ofs,
                                 SBC_AT_RP_IV_LEN,
                                 iv);

    //SBC_mem_print_bin("iv data =", iv, SBC_AT_RP_IV_LEN);

    //
    // Reading tag
    //
    rd_ofs += SBC_AT_RP_IV_LEN;
    ret  = SBC_RawAlignedReadBlockIO(p->blkhnd, 
                                 rd_ofs,
                                 SBC_AT_RP_TAG_LEN,
                                 tag);


    //SBC_mem_print_bin("tag data =", tag, SBC_AT_RP_TAG_LEN);
    //( p->bm == BOOT_MODE_UPDATE ) ? shared_secret = ((atp_ident_t *)p->keyinfo)->migid : shared_secret = dec_key;




    //
    // Decrypt the Protected SW 
    //

    ctx.msg.value = (void *)encbuf;
    ctx.out.value = (void *)decbuf;
    ctx.msg.length = ctx.out.length = enclen;

    aesctx.gcm = &ctx;
    aesctx.algoid = SBC_CIPHER_AES_GCM;

    //dprint("");
    SBC_AESGcmSetContext((void *)aesctx.gcm, 
                     (void *)shared_secret, 
                     (void *)iv, 
                     (void *)tag);

    //dprint("");
    if (SBC_AESGcmDecrypt(&aesctx) != SBCOK) {
        SBC_LogHexToStrChar16(shared_secret, 32, err_out_key_val, sizeof(err_out_key_val)/sizeof(err_out_key_val[0]),  FALSE, 0);
        UnicodeSPrint(mrgmsg,  sizeof mrgmsg, L"SBC_ProtSW_Update Failed to decrypt (%s) \n", err_out_key_val);
        sbc_err_sysprn(SBC_LOG_CMN_PRIO_ERR, 2,
                 SYS_LOG_HOST_BOOT,
                 SYS_LOG_APP_NAME,
                 SYS_LOG_CSC_NAME,
                 5,
                 SYS_LOG_EVT_DETECTION,
                 mrgmsg);
        ret = SBCENCFAIL;
        goto errdone;
    }

    //dprint("");
    *rdlen = enclen;


errdone:

    return ret;

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
    // Check the Range
    //
    if (ByteOffset >= TotalBytes ||
        ByteOffset + Length > TotalBytes)
        return EFI_INVALID_PARAMETER;

    //
    // ByteOffset --> Convert to LBA
    //
    UINT64 StartLba    = ByteOffset / BlockSize;
    UINTN  InnerOffset = (UINTN)(ByteOffset % BlockSize);

    UINTN EndOffset = InnerOffset + Length;
    UINTN BlockCount = (EndOffset + BlockSize - 1) / BlockSize;
    UINTN ReadSize   = BlockCount * BlockSize;

    //
    // prepare the aligned temp buffer 
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
    // Block unit reading
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
    // Copy only the necessary parts to the user buffer
    //
    CopyMem(Buffer, (UINT8*)Tmp + InnerOffset, Length);

    gBS->FreePages(Phys, EFI_SIZE_TO_PAGES(ReadSize));

    return EFI_SUCCESS;
}


SBCStatus SBC_OSID_KeyStore(void *context) 
{
    boot_proc_t *bp = (boot_proc_t *)context;
    SBCStatus ret = SBCOK;
    UINT8 *enckey[SYS_OSID_KEY_LEN] = { 0, };
//  UINT32 osidlen = 0UL;
//  UINT8 *osid_buf = NULL;
    UINT8 auth_iv[SBC_AT_IV_LEN] = { 0, };
    UINT8 auth_tag[SBC_AT_TAG_LEN] = { 0, }; 
    SBC_AESContext aesctx;
    SBC_AESGcmCtx  ctx; 
    UINT8 encbuf[SBC_AT_SYSCONF_CRT_MAX] = { 0, }; 
    UINT8 cpybuf[SBC_AT_SYSCONF_CRT_MAX] = { 0, }; 
    UINT32 id_len = 0; 
    UINT32 cpy_offset = 0; 

    atp_ident_t *key = ((atp_ident_t *)bp->keyinfo);

//  UINTN osid_ofs = SYS_CONF_START_OFS + SYS_CONF_OSID_OFS;

    ret = SBC_DeviceSecuirtyKeyCreate((VOID *)enckey);
    SBC_RET_VALIDATE_ERRCODEMSG((ret == SBCOK),
                                ret,
                                "Security Key Create fail");

    SBC_RngGeneration(key->osid,        // Seed
                      SYS_OSID_KEY_LEN,
                      SBC_AT_IV_LEN,
                      auth_iv); 

    aesctx.gcm = &ctx;
    aesctx.algoid = SBC_CIPHER_AES_GCM; 
    SBC_AESGcmSetContext((void *)aesctx.gcm,
                         (void *)enckey,
                         (void *)auth_iv,
                         (void *)auth_tag); 

    ctx.msg.value = (UINT8 *)key->osid;
    ctx.msg.length = SYS_OSID_KEY_LEN;
    ctx.out.value = encbuf;
    ctx.out.length = ctx.msg.length; 

    ret = SBC_AESGcmEncrypt(&aesctx);
    SBC_RET_VALIDATE_ERRCODEMSG((ret == SBCOK),
                                ret,
                                "Firmware ID Encrypt fail"); 

    cpy_offset = 0; 
    id_len = ctx.out.length;
    CopyMem(&cpybuf[cpy_offset], &id_len, 4);
    cpy_offset += 4;

    CopyMem(&cpybuf[cpy_offset],
            encbuf,
            id_len);
    
    cpy_offset += id_len;
    SBC_mem_print_bin("OSID encrypt", (UINT8 *)encbuf, id_len);
    // IV copy
    SBC_mem_print_bin("OSID IV", (UINT8 *)auth_iv, SBC_AT_IV_LEN);
    CopyMem(&cpybuf[cpy_offset],
            auth_iv,
            SBC_AT_IV_LEN);
    cpy_offset += SBC_AT_IV_LEN; 

    // Tag copy
    CopyMem(&cpybuf[cpy_offset],
            auth_tag,
            SBC_AT_TAG_LEN); 

    SBC_mem_print_bin("OSID TAG", (UINT8 *)auth_tag, SBC_AT_TAG_LEN);
    cpy_offset += SBC_AT_TAG_LEN; 


    ret = SBC_RawAlignedWriteBlockIO(bp->blkhnd,
                                     SYS_CONF_START_OFS + SYS_CONF_OSID_OFS,
                                     cpy_offset,
                                     cpybuf);


errdone:


    return ret;

}

SBCStatus SBC_BaseAnswerExtractFromDisk(VOID *blkio, base_ansid_t *p)
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
   dprint("SBC_RawPrtReadBlock fail (%p)\n", blkio);
    goto errdone;
  }
  //Print(L"%a:%d \n",__FUNCTION__, __LINE__);


  // Copy Length

  offset = SYS_CONF_RES_OFS;
  dprint("Offset : 0x%x", offset);
  CopyMem((void *)&p->msglen, (void *)&loadbuf[offset], 4);
  SBC_RET_VALIDATE_ERRCODEMSG((p->msglen > 0), SBCBSANSWNOTFND, "Base Answer Not Foudn");
  offset += 4;
    /* --- msglen range validation (NOTE 반영) --- */
//  {
//      UINTN max_payload =
//          ldlen - SYS_CONF_RES_OFS
//                - sizeof(UINT32)
//                - BASE_ANS_IV_KEY_STR
//                - BASE_ANS_TAG_LEN;
//
//      SBC_RET_VALIDATE_ERRCODEMSG((p->msglen <= max_payload),
//                                  SBCINVPARAM,
//                                  "Base Answer msglen overflow");
//  }
  CopyMem((void *)p->encmsg, (void *)&loadbuf[offset], p->msglen);
  offset += p->msglen;

#ifdef _TEST_BED_
  {
      dprint("*** 5.4.6.1 6.Encrypt Base Answer with OSID --->");
  }
#endif

  CopyMem((void *)p->iv, (void *)&loadbuf[offset], BASE_ANS_IV_KEY_STR);
  offset += BASE_ANS_IV_KEY_STR;


  CopyMem((void *)p->tag, (void *)&loadbuf[offset], BASE_ANS_TAG_LEN);
  offset += BASE_ANS_TAG_LEN;


errdone:

  if (loadbuf != NULL) {
      FreePool(loadbuf);
      loadbuf = NULL;
  }
  return ret;
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


EFI_STATUS SBC_CopyBlockDeviceToFileWithSize(
    IN VOID   *_Blk,
    IN UINT64  ByteOffset,
    IN CHAR16 *DstPath,
    OUT UINT64 *BytesRead OPTIONAL
)
{
    if (BytesRead) *BytesRead = 0;
    if (!_Blk || !DstPath) return EFI_INVALID_PARAMETER;

    EFI_STATUS Status;
    EFI_BLOCK_IO_PROTOCOL *Blk = (EFI_BLOCK_IO_PROTOCOL*)_Blk;

    //
    // Read 4 bytes starting from the offset to obtain the FileSize
    //
    UINT32 FileSize = 0;
    Status = SBC_RawReadSizeFromOffset(Blk, ByteOffset, &FileSize);
    if (EFI_ERROR(Status)) {
        dprint("Size read fail %r", Status);
        return Status;
    }

    dprint("FileSize = %u bytes", FileSize);

    //
    // BlockDevice Boundary Check
    //
    EFI_BLOCK_IO_MEDIA *m = Blk->Media;
    if (!m || !m->MediaPresent) return EFI_NO_MEDIA;

    UINT64 TotalBytes = (m->LastBlock + 1ULL) * m->BlockSize;

    if (ByteOffset + 4 + FileSize > TotalBytes)
        return EFI_VOLUME_CORRUPTED;    // Size of zero

    //
    // Write Open Target File
    //
    EFI_SIMPLE_FILE_SYSTEM_PROTOCOL *Fs;
    EFI_FILE_PROTOCOL *Root, *OutFile;

    Status = gBS->LocateProtocol(&gEfiSimpleFileSystemProtocolGuid, NULL, (VOID**)&Fs);
    if (EFI_ERROR(Status)) return Status;

    Status = Fs->OpenVolume(Fs, &Root);
    if (EFI_ERROR(Status)) return Status;

    Status = Root->Open(
                Root,
                &OutFile,
                DstPath,
                EFI_FILE_MODE_READ | EFI_FILE_MODE_WRITE | EFI_FILE_MODE_CREATE,
                0);
    if (EFI_ERROR(Status)) {
        Root->Close(Root);
        return Status;
    }

    //
    // Copy File chunks to BlockDevice for FileSize
    //
    UINT64 remaining = FileSize;
    UINT64 offset    = ByteOffset + 4;  // Data starts 4 bytes after Size
    UINT64 copied    = 0;

    UINT8 *buf = AllocatePool(FILE_CHUNK_SZ);
    if (!buf) {
        OutFile->Close(OutFile);
        Root->Close(Root);
        return EFI_OUT_OF_RESOURCES;
    }

    while (remaining > 0) {
        UINTN chunk = (remaining > FILE_CHUNK_SZ) ? FILE_CHUNK_SZ : (UINTN)remaining;

        Status = SBC_BlkReadArbitrary(Blk, offset, buf, chunk);
        if (EFI_ERROR(Status)) {
            dprint("Read error %r", Status);
            break;
        }

        UINTN wr = chunk;
        Status = OutFile->Write(OutFile, &wr, buf);
        if (EFI_ERROR(Status)) {
            dprint("File write error %r", Status);
            break;
        }

        offset    += chunk;
        remaining -= chunk;
        copied    += chunk;

        UINTN pct = (UINTN)((copied * 100) / FileSize);
        Print(L"\rCopying: %3u%%", pct);
    }

    Print(L"\rCopying: 100%%\n");

    FreePool(buf);

    OutFile->Close(OutFile);
    Root->Close(Root);

    if (BytesRead) *BytesRead = copied;
    return Status;
}


EFI_STATUS SBC_RawReadSizeFromOffset(
    IN  EFI_BLOCK_IO_PROTOCOL *Blk,
    IN  UINT64                 ByteOffset,
    OUT UINT32                *OutSize
)
{
    if (!Blk || !OutSize) return EFI_INVALID_PARAMETER;

    EFI_STATUS Status;
    UINT8 szbuf[4];

    //
    // Read the first 4 bytes 
    //
    Status = SBC_BlkReadArbitrary(Blk, ByteOffset, szbuf, 4);
    if (EFI_ERROR(Status))
        return Status;

    //
    // Zero block check 
    //
    if (szbuf[0] == 0 && szbuf[1] == 0 && szbuf[2] == 0 && szbuf[3] == 0)
        return EFI_COMPROMISED_DATA;

    //
    // convert to littile endian
    //
    *OutSize =
        (szbuf[0]) |
        (szbuf[1] << 8) |
        (szbuf[2] << 16) |
        (szbuf[3] << 24);

    dprint("FW Data Size : %d", *OutSize);

    if (*OutSize == 0)
        return EFI_BAD_BUFFER_SIZE;

    return EFI_SUCCESS;
}

static
EFI_STATUS
GetFileSizeOnMyFs(
    IN  EFI_HANDLE ImageHandle,
    IN  CHAR16    *AbsPath,
    OUT UINT64    *FileSize
    )
{
    if (!AbsPath || !FileSize)
        return EFI_INVALID_PARAMETER;

    EFI_STATUS Status;
    EFI_LOADED_IMAGE_PROTOCOL *LoadedImage = NULL;
    EFI_SIMPLE_FILE_SYSTEM_PROTOCOL *Fs = NULL;
    EFI_FILE_PROTOCOL *Root = NULL;
    EFI_FILE_PROTOCOL *File = NULL;
    EFI_FILE_INFO *Info = NULL;
    UINTN InfoSz = 0;

    Status = gBS->HandleProtocol(
                    ImageHandle,
                    &gEfiLoadedImageProtocolGuid,
                    (VOID**)&LoadedImage
                );
    if (EFI_ERROR(Status) || !LoadedImage)
        return EFI_NOT_FOUND;

    Status = gBS->HandleProtocol(
                    LoadedImage->DeviceHandle,
                    &gEfiSimpleFileSystemProtocolGuid,
                    (VOID**)&Fs
                );
    if (EFI_ERROR(Status) || !Fs)
        return Status;

    Status = Fs->OpenVolume(Fs, &Root);
    if (EFI_ERROR(Status) || !Root)
        return Status;

    Status = Root->Open(Root, &File, AbsPath, EFI_FILE_MODE_READ, 0);
    if (EFI_ERROR(Status)) {
        Root->Close(Root);
        return Status;
    }

    Status = File->GetInfo(File, &gEfiFileInfoGuid, &InfoSz, NULL);
    if (Status != EFI_BUFFER_TOO_SMALL) {
        File->Close(File);
        Root->Close(Root);
        return Status;
    }

    Info = AllocateZeroPool(InfoSz);
    if (!Info) {
        File->Close(File);
        Root->Close(Root);
        return EFI_OUT_OF_RESOURCES;
    }

    Status = File->GetInfo(File, &gEfiFileInfoGuid, &InfoSz, Info);
    if (EFI_ERROR(Status)) {
        FreePool(Info);
        File->Close(File);
        Root->Close(Root);
        return Status;
    }

    *FileSize = Info->FileSize;

    FreePool(Info);
    File->Close(File);
    Root->Close(Root);
    return EFI_SUCCESS;
}

EFI_STATUS
SBC_EFI_FSBL_Load(LV_t *lv)
{
    if (!lv)
        return EFI_INVALID_PARAMETER;

#ifndef _SSBL_TEST_RUN_
    CHAR16 *TargetPath = L"\\EFI\\BOOT\\bootx64.efi";
#else
    CHAR16 *TargetPath = L"\\EFI\\BOOT\\FSBL.efi";
#endif

    EFI_STATUS Status;
    UINT64 FileSize = 0;

    lv->value  = NULL;
    lv->length = 0;

    //
    // 1) Get file size (using the filesystem of current loaded image)
    //
    Status = GetFileSizeOnMyFs(gImageHandle, TargetPath, &FileSize);
    if (EFI_ERROR(Status)) {
        return Status;
    }

    //
    // 2) Allocate buffer and set length for SBC_ReadFile()
    //
    lv->value = AllocatePool((UINTN)FileSize);
    if (!lv->value)
        return EFI_OUT_OF_RESOURCES;

    lv->length = FileSize;

    //
    // 3) Read file using your existing SBC_ReadFile()
    //    IMPORTANT: SBC_ReadFile() expects ImageHandle to be a handle that
    //               supports SimpleFS. Your current implementation uses
    //               HandleProtocol(ImageHandle, SimpleFS), which usually fails
    //               if ImageHandle is gImageHandle.
    //
    //    To keep using SBC_ReadFile() WITHOUT changing it, we must pass a handle
    //    that actually has SimpleFS installed.
    //
    //    Therefore, we will resolve the filesystem device handle and pass it.
    //
    EFI_LOADED_IMAGE_PROTOCOL *LoadedImage = NULL;
    Status = gBS->HandleProtocol(
                    gImageHandle,
                    &gEfiLoadedImageProtocolGuid,
                    (VOID**)&LoadedImage
                );
    if (EFI_ERROR(Status) || !LoadedImage) {
        FreePool(lv->value);
        lv->value = NULL;
        lv->length = 0;
        return EFI_NOT_FOUND;
    }

    //
    // Use the device handle (ESP partition handle) that has SimpleFS
    //
    Status = SBC_ReadFile(LoadedImage->DeviceHandle, TargetPath, lv);
    if (EFI_ERROR(Status)) {
        FreePool(lv->value);
        lv->value = NULL;
        lv->length = 0;
        return Status;
    }

    return EFI_SUCCESS;
}

/**
 * @fn SBC_EFI_SSBL_Load
 * @brief Locate and load the SSBL EFI image from an accessible EFI filesystem into memory.
 *
 * This function finds an EFI SimpleFS handle that can access the SSBL image
 * located at <code>EFI_BOOT_SSBL_PATH</code>, allocates a buffer sized to the
 * file, and loads the file content into @p lv.
 *
 * @param[in]  ImageHandle
 *      Current image handle (reserved for future use; not used in current implementation).
 *
 * @param[in,out] lv
 *      Pointer to LV_t output container.
 *      On success:
 *        - lv->value  points to newly allocated buffer containing SSBL image
 *        - lv->length is set to SSBL image size in bytes
 *
 * @retval SBCOK
 *      SSBL loaded successfully.
 *
 * @retval SBCFAIL
 *      Failed to find an EFI filesystem handle that can access the SSBL file, or other fatal error.
 *
 * @retval SBCNULLP
 *      Memory allocation failed.
 *
 * @retval SBCNOTFND
 *      SSBL file access succeeded, but read operation failed.
 *
 * @retval Others
 *      Propagated SBCStatus from SBC_GetFileSize() or internal validations.
 *
 * @details
 * Processing steps:
 *
 * Step 1. Query SSBL file size using <code>SBC_GetFileSize(EFI_BOOT_SSBL_PATH)</code>.
 *         If not found or error occurs, return the error status.
 *
 * Step 2. Enumerate EFI filesystem handles via <code>SBC_FindEfiFileSystemProtocol()</code>.
 *         If none are found, return <code>SBCFAIL</code>.
 *
 * Step 3. Iterate over filesystem handles and check accessibility of
 *         <code>EFI_BOOT_SSBL_PATH</code> via <code>SBC_IsFlieAccess()</code>.
 *         Stop at the first handle that can access the file.
 *
 * Step 4. If no filesystem handle can access the SSBL file, return <code>SBCFAIL</code>.
 *
 * Step 5. Allocate a zero-initialized buffer of <code>len_of_kernel</code> bytes,
 *         assign it to <code>lv->value</code>, and set <code>lv->length</code>.
 *
 * Step 6. Read the SSBL file content using <code>SBC_ReadFile()</code> with the selected
 *         filesystem handle.
 *         If read fails, set <code>ret = SBCNOTFND</code> and return.
 *
 * Step 7. Return <code>SBCOK</code> on success.
 *
 * @note
 * - The caller is responsible for freeing <code>lv->value</code> with <code>FreePool()</code>.
 * - Consider validating <code>lv</code> is not NULL before use.
 * - Consider initializing <code>Status</code> before the loop to avoid using an
 *   uninitialized value if the loop does not find a valid handle.
 * - If <code>SBC_FindEfiFileSystemProtocol()</code> allocates <code>hndl</code>,
 *   define ownership and free it accordingly to avoid leaks.
 */
SBCStatus SBC_EFI_SSBL_Load(EFI_HANDLE ImageHandle, LV_t *lv)
{

    SBCStatus           ret = SBCOK;
    EFI_STATUS          Status;
    UINTN               len_of_kernel = 0;
    UINTN               hndlcnt;
    UINTN               idx;
    EFI_HANDLE          *hndl;


    //dprint();
    ret = SBC_GetFileSize( EFI_BOOT_SSBL_PATH, &len_of_kernel);
    SBC_RET_VALIDATE_ERRCODEMSG((ret == SBCOK), ret, "File Not Found");
    //dprint();
    hndlcnt = SBC_FindEfiFileSystemProtocol(&hndl);
    if (hndlcnt <= 0) {
      eprint("File System Handle find fail : %d", hndlcnt);
      return SBCFAIL;
    }
    //dprint();
    for (idx = 0; idx < hndlcnt; idx++) {
      Status = SBC_IsFlieAccess(hndl[idx], EFI_BOOT_SSBL_PATH);
      if (EFI_ERROR(Status)) {
        continue;
      }

      break;
    }
    //dprint();

    if (EFI_ERROR(Status)) {
        eprint("%s  : %r", EFI_BOOT_SSBL_PATH, Status);
        return SBCFAIL;
    }

    //dprint();
    lv->value = AllocateZeroPool(len_of_kernel);
    lv->length = len_of_kernel;
    dprint("%s size %d", EFI_BOOT_SSBL_PATH, lv->length);
    SBC_RET_VALIDATE_ERRCODEMSG((lv->value != NULL), SBCNULLP, "Out of Memory");

    //dprint();

    Status = SBC_ReadFile(hndl[idx], EFI_BOOT_SSBL_PATH, lv);
    if (EFI_ERROR(Status)) {
      eprint("%s file read fail with %r", EFI_BOOT_SSBL_PATH, Status);
      ret = SBCNOTFND;
      goto errdone;
    }

    //ssbl_lv = lv;


    //dprint();
errdone:
    return ret;

}

static SBCStatus _find_kernel_path(CHAR16 **buf, UINTN *len_of_kernel)
{
    SBCStatus ret = SBCOK;

    ret = SBC_FileReadUnicodeSimple(KERNEL_DIR_FILE, buf, len_of_kernel);

    //SBC_mem_print_bin("Kernel path" , buf, *len_of_kernel);

    //dprint("kernel path : %s (count : %d )", (CHAR16 *)*buf, *len_of_kernel);

    return ret;

} 
/**
 * @fn SBC_EFI_Kernel_Load
 * @brief Locate and load the Linux kernel image from an accessible EFI filesystem into memory.
 *
 * This function resolves the kernel path, finds an EFI SimpleFS handle that can
 * access the kernel file, allocates a buffer sized to the kernel image, and
 * loads the file content into @p lv.
 *
 * @param[in]  ImageHandle
 *      Current image handle (reserved for future use; not used in current implementation).
 *
 * @param[in,out] lv
 *      Pointer to LV_t output container.
 *      On success:
 *        - lv->value  points to newly allocated buffer containing the kernel image
 *        - lv->length is set to the kernel image size in bytes
 *      On failure:
 *        - lv->value may be NULL (or stale if caller didn't pre-init); caller should initialize it.
 *
 * @retval SBCOK
 *      Kernel loaded successfully.
 *
 * @retval SBCFAIL
 *      Failed to find a filesystem handle that can access the kernel, or other fatal error.
 *
 * @retval SBCNULLP
 *      Memory allocation failed.
 *
 * @retval SBCNOTFND
 *      Kernel file exists but read operation failed.
 *
 * @retval Others
 *      Propagated SBCStatus from SBC_GetFileSize() or internal validations.
 *
 * @details
 * Processing steps:
 *
 * Step 1. Resolve the kernel path by calling <code>_find_kernel_path()</code>
 *         which sets <code>kernel_name</code> and (optionally) <code>len_of_kernel</code>.
 *
 * Step 2. Query the kernel file size using <code>SBC_GetFileSize()</code>.
 *         If the file is not found or size query fails, return the error.
 *
 * Step 3. Enumerate EFI filesystem handles via <code>SBC_FindEfiFileSystemProtocol()</code>.
 *         If none are found, return <code>SBCFAIL</code>.
 *
 * Step 4. Iterate over filesystem handles and test accessibility using
 *         <code>SBC_IsFlieAccess()</code>. Stop at the first handle that can access
 *         <code>kernel_name</code>.
 *
 * Step 5. If no handle can access the file, return <code>SBCFAIL</code>.
 *
 * Step 6. Allocate a zero-initialized buffer of <code>len_of_kernel</code> bytes,
 *         assign it to <code>lv->value</code>, and set <code>lv->length</code>.
 *
 * Step 7. Read the kernel file using <code>SBC_ReadFile()</code> with the selected
 *         filesystem handle. On read failure, set <code>ret = SBCNOTFND</code> and return.
 *
 * Step 8. Return <code>SBCOK</code> on success.
 *
 * @note
 * - The caller is responsible for freeing <code>lv->value</code> with <code>FreePool()</code>.
 * - Current implementation does not free <code>kernel_name</code> (if dynamically allocated)
 *   and does not free <code>hndl</code> (if allocated by SBC_FindEfiFileSystemProtocol()).
 *   Ensure ownership rules are defined to avoid leaks.
 * - Consider initializing <code>Status</code> before the loop to avoid using an
 *   uninitialized value if <code>hndlcnt</code> is 0 or loop does not execute.
 */
SBCStatus SBC_EFI_Kernel_Load(EFI_HANDLE ImageHandle, LV_t *lv)
{
    SBCStatus           ret = SBCOK;
    EFI_STATUS          Status;
    UINTN               len_of_kernel = 0;
    UINTN               hndlcnt;
    UINTN               idx;
    EFI_HANDLE          *hndl;
//  CHAR16 kernel_name[512] = {
//      [0 ... 511] = 0
//  };

    CHAR16 *kernel_name = NULL;


    _find_kernel_path((CHAR16 **)&kernel_name, &len_of_kernel);
    dprint("kernel name : %s (len :%ld) ", kernel_name, len_of_kernel);

    ret = SBC_GetFileSize( kernel_name, &len_of_kernel);
    SBC_RET_VALIDATE_ERRCODEMSG((ret == SBCOK), ret, "File Not Found");
    //dprint();
    hndlcnt = SBC_FindEfiFileSystemProtocol(&hndl);
    if (hndlcnt <= 0) {
      eprint("File System Handle find fail : %d", hndlcnt);
      return SBCFAIL;
    }
    //dprint();
    for (idx = 0; idx < hndlcnt; idx++) {
      Status = SBC_IsFlieAccess(hndl[idx], kernel_name);
      if (EFI_ERROR(Status)) {
        continue;
      }

      break;
    }
    //dprint();

    if (EFI_ERROR(Status)) {
        eprint("%s  : %r", kernel_name, Status);
        return SBCFAIL;
    }

    //dprint();
    lv->value = AllocateZeroPool(len_of_kernel);
    lv->length = len_of_kernel;
    dprint("%s size %d", kernel_name, lv->length);
    SBC_RET_VALIDATE_ERRCODEMSG((lv->value != NULL), SBCNULLP, "Out of Memory");

    //dprint();

    Status = SBC_ReadFile(hndl[idx], kernel_name, lv);
    if (EFI_ERROR(Status)) {
      eprint("%s file read fail with %r", kernel_name, Status);
      ret = SBCNOTFND;
      goto errdone;
    }


    //dprint();
errdone:
    return ret;
}