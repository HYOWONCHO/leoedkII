#include <Uefi.h>
#include <Library/UefiBootServicesTableLib.h>
#include <Library/UefiRuntimeServicesTableLib.h>
#include <Library/UefiLib.h>
#include <Library/BaseMemoryLib.h>
#include <Library/MemoryAllocationLib.h>
#include <Guid/FileInfo.h>
#include <Protocol/BlockIo.h>
#include <Protocol/DevicePathToText.h>

#include <string.h>

#include "SBC_Util.h"
#include "SBC_FileCtrl.h"

//static UINT32 _get_rw_blkcnt(UINT32 bytes)
//{
////  UINTN       division;
////  UINTN       quotient;
////
////  //quteint = bytes % SBC_RAWPTR_DFLT_BLK_SZ;
////
////  division =
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
    DEBUG((DEBUG_ERROR, " %a:%d Locate File Systam fail (%d) \r\n",
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
//DEBUG((DEBUG_ERROR,"Image Handle : %p \r\n", ImageHandle));
//DEBUG((DEBUG_ERROR,"Read File : %s \r\n", (CHAR8 *)FileNames));

  dprint("Read File : %s", FileNames);

  // Locate file system
  Status = gBS->HandleProtocol(ImageHandle,
                               &gEfiSimpleFileSystemProtocolGuid,
                               (VOID **)&FileSystem);
  if(EFI_ERROR(Status)) {
    DEBUG((DEBUG_ERROR, " %a:%d Locate File Systam fail (%d) \r\n",
           __FUNCTION__, __LINE__, Status));
    return Status;
  }

  // Open the roor directory
  Status = FileSystem->OpenVolume(FileSystem, &RootDir);
  if (EFI_ERROR(Status)) {
        DEBUG((DEBUG_ERROR, " %a:%d OpenVolume File Systam fail (%d) \r\n",
           __FUNCTION__, __LINE__, Status));
    return Status;
  }

  // Open the file
  Status = RootDir->Open(RootDir, &File, FileNames, EFI_FILE_MODE_READ, 0);
  if (EFI_ERROR(Status)) {
      DEBUG((DEBUG_ERROR, " %a:%d RootDir->Open fail (%d) \r\n",
     __FUNCTION__, __LINE__, Status));
    return Status;
  }

  // Read the file
  Status = File->Read(File, (UINTN *)&out->length, out->value);
  if (EFI_ERROR(Status)) {
      DEBUG((DEBUG_ERROR, " %a:%d File->Read fail (%d) \r\n",
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
    DEBUG((DEBUG_ERROR, " %a:%d Locate File Systam fail (%d) \r\n",
           __FUNCTION__, __LINE__, Status));
    return Status;
  }

  // Open the roor directory
  Status = FileSystem->OpenVolume(FileSystem, &RootDir);
  if (EFI_ERROR(Status)) {
        DEBUG((DEBUG_ERROR, " %a:%d OpenVolume File Systam fail (%d) \r\n",
           __FUNCTION__, __LINE__, Status));
    return Status;
  }

  // Open the file
  Status = RootDir->Open(RootDir, &File, FileNames, EFI_FILE_MODE_READ | EFI_FILE_MODE_WRITE | EFI_FILE_MODE_CREATE, 0);
  if (EFI_ERROR(Status)) {
      DEBUG((DEBUG_ERROR, " %a:%d RootDir->Open fail (%d) \r\n",
     __FUNCTION__, __LINE__, Status));
    return Status;
  }

  // Read the file
  Status = File->Write(File, (UINTN *)&out->length, out->value);
  if (EFI_ERROR(Status)) {
      DEBUG((DEBUG_ERROR, " %a:%d File->Read fail (%d) \r\n",
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
        Print(L"gEfiSimpleFileSystemProtocolGuid foud fail (%r) \n", retval);
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
        DEBUG((DEBUG_ERROR, " %a:%d OpenVolume File Systam fail (%d) \r\n",
           __FUNCTION__, __LINE__, Status));
        return SBCBADFMT;
    }

    Status = RootDir->Open(RootDir, &File, fname,
                           EFI_FILE_MODE_READ |EFI_FILE_MODE_WRITE | EFI_FILE_MODE_CREATE,
                           0);
    if(EFI_ERROR(Status)) {
        DEBUG((DEBUG_ERROR, " %a:%d RootDir->Open fail (%d) \r\n",
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
        DEBUG((DEBUG_ERROR, " %a:%d OpenVolume File Systam fail (%d) \r\n",
           __FUNCTION__, __LINE__, Status));
        return SBCBADFMT;
    }

    Status = RootDir->Open(RootDir, &File, fname,
                           EFI_FILE_MODE_READ |EFI_FILE_MODE_WRITE | EFI_FILE_MODE_CREATE,
                           EFI_FILE_DIRECTORY);
    if(EFI_ERROR(Status)) {
        DEBUG((DEBUG_ERROR, " %a:%d RootDir->Open fail (%d) \r\n",
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

    dprint("key : %a , keylen :%d", key, strlen(key));
    for (INT32 x = 0; x < nkeys; x++) {
        bm_lookup_table_t *sym = &tb[x];
        dprint("sym key : %a , Len :%d", sym->key, strlen(sym->key));
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

    SBC_external_mem_print_bin("Boot Mode", rdbuf, 16);
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
        Print(L"No Block IO device found ( %d )\n", Status);
        goto errdone;

    }
//  else {
//      Print(L"Found %d Block IO device \n" , HandleCount);
//  }

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
        Print(L"Allocate Pool fail \n");
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
        Print(L"Read Heade Info fail(%d) %r \n", retval, retval);
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
    SBC_RET_VALIDATE_ERRCODEMSG(((rdbuf != NULL) || (rdlen != NULL)), SBCNULLP, "Invalid parameter");
    SBC_RET_VALIDATE_ERRCODEMSG((*rdlen != 0), SBCZEROL, "Invalid parameter");

    blkio  = (EFI_BLOCK_IO_PROTOCOL *)blkhnd;

//  blklen = ALIGN_VALUE(*rdlen, blkio->Media->BlockSize);
//  //Print(L"BLK Len : %d \n", blklen);
//  readbuf = AllocateZeroPool(blklen);
//  if (readbuf == NULL) {
//      Print(L"Allocate Pool fail \n");
//      ret = SBCNULLP;
//      goto errdone;
//  }


    retval = blkio->ReadBlocks(
                blkio,
                blkio->Media->MediaId,
                rlba,
                *rdlen,
                rdbuf
        );

    if (EFI_ERROR(retval)) {
        Print(L"Read Heade Info fail(%d) %r \n", retval, retval);
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
    //int idx;
//  int leftcnt = 0;
//  int leftcpy = 0;
    UINT8 *wrp = NULL;
    EFI_BLOCK_IO_PROTOCOL           *p = NULL;

    SBC_RET_VALIDATE_ERRCODEMSG(((p != NULL) || (wrbuf != NULL)), SBCNULLP, "Invalid Parameter");
    SBC_RET_VALIDATE_ERRCODEMSG((wrlen != 0), SBCZEROL, "Invalid Parameter");

    p = (EFI_BLOCK_IO_PROTOCOL *)blkio;
    wrp = wrbuf;

//  leftcnt = wrlen / p->Media->BlockSize;
//  leftcpy = wrlen % p->Media->BlockSize;


    retval = p->WriteBlocks(
                    p,
                    p->Media->MediaId,
                    wrlba,
                    p->Media->BlockSize ,
                    //(wrlen % p->Media->BlockSize == 0) ? wrlen : p->Media->BlockSize ,
                    wrp
        );

    if(EFI_ERROR(retval)) {
        Print(L"Write Block I/O fail : %r", retval);
        ret = SBCIO;
        goto errdone;
    }
//      wrp += p->Media->BlockSize;
//      wrlba++;
//      leftcnt--;
//
//
//
//  retval = p->WriteBlocks(
//                  p,
//                  p->Media->MediaId,
//                  wrlba,
//                  leftcpy,
//                  //(wrlen % p->Media->BlockSize == 0) ? wrlen : p->Media->BlockSize ,
//                  wrp
//      );
//
//  if(EFI_ERROR(retval)) {
//      Print(L"Last Write Block I/O fail : %r", retval);
//      ret = SBCIO;
//      goto errdone;
//  }

errdone:
    return ret;

}

SBCStatus  SBC_BlkIoHandleInit(OUT VOID **hblk, OUT VOID *hdr)
{
#define     SBC_MAGIC_LEN           0x04
#define     SBC_MAGIC_ID            0xAA55AA55

    SBCStatus                       ret;
    EFI_STATUS                      Status;
    EFI_HANDLE                      *HandleBuffer = NULL;
    UINTN                           NumberOfHandles;
    VOID                            *ReadBuffer = NULL; // Buffer for raw block data
    EFI_BLOCK_IO_PROTOCOL           *BlockIo = NULL;
    UINT32                           magicid = 0UL;
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
        Print(L"ERROR: Failed to locate BlockIoProtocol handles: %r\n", Status);
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
            Print(L"RROR: Could not open BlockIoProtsocol %r\n", Status);
            SBC_RET_VALIDATE_ERRCODEMSG((Status != EFI_SUCCESS), SBCFAIL, "ERROR: Could not open BlockIoProtocol");
        }

        //blkiosz = MultU64x32(BlockIo->Media->LastBlock + 1, BlockIo->Media->BlockSize);
        //Print(L"Found %p Block I/O Protocol Address.\n", BlockIo);


        //Print(L"INFO: Found SBC Raw Partiiton %r\n", Status);

        ReadBuffer = AllocatePool(BlockIo->Media->BlockSize);
        if (ReadBuffer == NULL) {
             Print(L"Buffer allocatino fail \n");
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
            Print(L"ERROR: Failed to read LBA 0: %r\n", Status);
            SBC_RET_VALIDATE_ERRCODEMSG((Status != EFI_SUCCESS), SBCFAIL, "ERROR: Could not open BlockIoProtocol");
            ret = SBCFAIL;
            goto errdone;
        }

        //SBC_mem_print_bin("Read Block", (UINT8 *)ReadBuffer, SBC_MAGIC_LEN);
        //CopyMem((void *)&magicid, (VOID *)&((UINT8 *)ReadBuffer)[0],SBC_MAGIC_LEN);
        CopyMem((void *)hdr, (VOID *)&((UINT8 *)ReadBuffer)[0], sizeof(rawprt_hdr_t));


        //SBC_mem_print_bin("Header buf", (UINT8 *)hdr, 16);

        FreePool(ReadBuffer);      

        ((rawprt_hdr_t *)hdr)->magicid  = SBC_SWAP_ENDIAN_32(((rawprt_hdr_t *)hdr)->magicid);
        //Print(L"%d Magic ID : 0x%x \n", idx, ((rawprt_hdr_t *)hdr)->magicid);

        
        
        if (((rawprt_hdr_t *)hdr)->magicid != SBC_RAWPRT_MAGIC_ID) {
            continue;
        }

        *hblk = (VOID *)BlockIo;
        Print(L"Found %p Block I/O Protocol Address Magci ID : 0x%x.\n", BlockIo, magicid);
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
//  Print(L"Enumerating block devices...\n");
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
//    Print(L"ERROR: Failed to locate BlockIoProtocol handles: %r\n", Status);
//    return Status;
//  }
//
//  Print(L"Found %d Block I/O Protocol handles.\n", NumberOfHandles);
//
//  // (Optional) Locate DevicePathToTextProtocol for printing
//  gBS->LocateProtocol (&gEfiDevicePathToTextProtocolGuid, NULL, (VOID **)&DevicePathToText);
//
//  //
//  // 2. Iterate through each handle and get Block IO information.
//  //
//  for (Index = 0; Index < NumberOfHandles; Index++) {
//    Print(L"\n--- Handle %d ---\n", Index);
//
//    // Get the Block I/O Protocol interface
//    Status = gBS->HandleProtocol (
//                    HandleBuffer[Index],
//                    &gEfiBlockIoProtocolGuid,
//                    (VOID **)&BlockIo
//                    );
//    if (EFI_ERROR (Status)) {
//      Print(L"  ERROR: Could not open BlockIoProtocol: %r\n", Status);
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
//      Print(L"  WARNING: No Device Path Protocol for this handle: %r\n", Status);
//      DevicePath = NULL; // Ensure it's NULL if not found
//    }
//
//    // Print device path string (if protocol available)
//    if (DevicePath != NULL && DevicePathToText != NULL) {
//      DevicePathStr = DevicePathToText->ConvertDevicePathToText (DevicePath, FALSE, FALSE);
//      if (DevicePathStr != NULL) {
//        Print(L"  Device Path: %s\n", DevicePathStr);
//        FreePool(DevicePathStr);
//        DevicePathStr = NULL; // Reset for next iteration
//      }
//    } else if (DevicePath != NULL) {
//      Print(L"  Device Path present, but DevicePathToTextProtocol not found.\n");
//    }
//
//    // Print Block I/O Media information
//    Print(L"  Media ID: %u\n", BlockIo->Media->MediaId);
//    Print(L"  Removable Media: %a\n", BlockIo->Media->RemovableMedia ? "TRUE" : "FALSE");
//    Print(L"  Media Present: %a\n", BlockIo->Media->MediaPresent ? "TRUE" : "FALSE");
//    Print(L"  Logical Prt: %a\n", BlockIo->Media->LogicalPrt ? "TRUE" : "FALSE");
//    Print(L"  Read Only: %a\n", BlockIo->Media->ReadOnly ? "TRUE" : "FALSE");
//    Print(L"  Block Size: %u bytes\n", BlockIo->Media->BlockSize);
//    Print(L"  Last Block LBA: 0x%Lx\n", BlockIo->Media->LastBlock);
//    Print(L"  Total Size: %Lu bytes\n", MultU64x32(BlockIo->Media->LastBlock + 1, BlockIo->Media->BlockSize));
//
//
//    //
//    // Example: Reading the first block (LBA 0) of the current device/Prt
//    //
//    if (BlockIo->Media->MediaPresent && !BlockIo->Media->ReadOnly && BlockIo->Media->BlockSize > 0) {
//        // Allocate a buffer for one block of data
//        ReadBuffer = AllocatePool(BlockIo->Media->BlockSize);
//        if (ReadBuffer == NULL) {
//            Print(L"  ERROR: Failed to allocate buffer for block read.\n");
//            // Continue to next handle or return
//        } else {
//            Print(L"  Attempting to read LBA 0 (size %u bytes)...\n", BlockIo->Media->BlockSize);
//            Status = BlockIo->ReadBlocks(
//                                  BlockIo,
//                                  BlockIo->Media->MediaId,
//                                  0, // LBA 0
//                                  BlockIo->Media->BlockSize,
//                                  ReadBuffer
//                                  );
//            if (EFI_ERROR(Status)) {
//                Print(L"  ERROR: Failed to read LBA 0: %r\n", Status);
//            } else {
//                Print(L"  Successfully read LBA 0.\n");
//                // You can now inspect 'ReadBuffer' to see the raw data.
//                // For example, if it's a disk, LBA 0 might contain MBR or GPT header.
//                // Print(L"  First 16 bytes of LBA 0: ");
//                // for (UINTN i = 0; i < 16; i++) {
//                //   Print(L"%02x ", ((UINT8*)ReadBuffer)[i]);
//                // }
//                // Print(L"\n");
//            }
//            FreePool(ReadBuffer); // Always free the buffer
//            ReadBuffer = NULL;
//        }
//    } else {
//        Print(L"  Cannot read from this device (media not present, read-only, or block size is 0).\n");
//    }
//  }
//
//  if (HandleBuffer != NULL) {
//    FreePool(HandleBuffer);
//  }
//
//  return EFI_SUCCESS;
//}


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
