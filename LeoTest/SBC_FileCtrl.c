#include <Uefi.h>
#include <Library/UefiBootServicesTableLib.h>
#include <Library/UefiRuntimeServicesTableLib.h>
#include <Library/UefiLib.h>

#include "SBC_FileCtrl.h"
#include "SBC_Log.h"
#include "SBC_ErrorType.h"

UINTN  SBC_FileSysHandleBuffer(EFI_HANDLE *handle)
{
#if 0
  EFI_STATUS Status;
  EFI_HANDLE *h;
  UINTN hdlcnt = 0;
   DEBUG((DEBUG_ERROR, "Buffer finding !!! \n"));
  // Confirm that the Protocol Available
  Status = gBS->LocateHandleBuffer(ByProtocol,
                                  x &gEfiSimpleFileSystemProtocolGuid,
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
#endif

    return 0;
}

#if 0
SBCStatus  SBC_CreateFile(EFI_HANDLE h, CHAR16 *fname)
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
        return SBCBADDMT;
    }

    Status = RootDir->Open(RootDir, &File, fname,
                           EFI_FILE_MODE_READ |EFI_FILE_MODE_CREATE | EFI_FILE_MODE_WRITE,
                           0);
    if(EFI_ERROR(Status)) {
    if(EFI_ERROR(Status)) {
        DEBUG((DEBUG_INFO, " %a:%d RootDir->Open fail (%d) \r\n",
           __FUNCTION__, __LINE__, Status));
        return SBCBADDMT;
    }

    File->Close(File);

    return SBCOK;



}
#endif
