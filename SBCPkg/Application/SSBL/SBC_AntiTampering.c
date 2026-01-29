/********************************************************************************
 * Copyright (C) 2024 by Security Platform Inc.                                 *
 * This file is part of the SBC Project.                                        *
 *                                                                              *
 * This software contains confidential and proprietary information of           *
 * Security Platform Inc. Unauthorized reproduction, distribution, or           *
 * disclosure of this software, in whole or in part, is strictly prohibited.    *
 ********************************************************************************/

/**
 * @file SBC_Antitampering.c
 * @brief Secure Boot Certificate verification and integrity check for SSBL (Second Stage Boot Loader).
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


#include <Library/BaseMemoryLib.h>
#include <Library/MemoryAllocationLib.h>
#include <Library/BaseLib.h>
#include <Protocol/Smbios.h> // System Management BIOS header
#include <Uefi.h>
#include <Library/PcdLib.h>
#include <Library/UefiLib.h>
#include <Library/UefiBootServicesTableLib.h>
#include <Protocol/Smbios.h>
#include <Library/BaseLib.h>


// NVME parsing 
#include <Ppi/NvmExpressPassThru.h>
#include <IndustryStandard/Nvme.h>
#include <Guid/FileInfo.h>
#include <Protocol/DevicePathToText.h>
#include <Protocol/LoadedImage.h>
#include <Library/BaseCryptLib.h>
#include <Protocol/BlockIo.h>

#include <Library/DevicePathLib.h>

#include "SBC_BootProc.h"
#include "SBC_CryptAES.h"
#include "SBC_TypeDefs.h"

#include "SBC_Util.h"
#include "SBC_Config.h"
#include "SBC_FileCtrl.h"

#include "SBC_Hashing.h"
#include "SBC_AntiTampering.h"
#include "SBC_EccSignVerify.h"
#include "SBC_X509.h"
#include "SBC_Kdf.h" 
#include "SBC_Log.h"

#include "SBC_Nvram.h"
#include "SBC_SystemControl.h"
  
extern CHAR16 mrgmsg[8192];
CHAR16 print_out_key[128];


//static LV_t *fsbl_lv;
//static LV_t *ssbl_lv;




extern VOID *h_blkio;
static boot_proc_t *btctx = NULL;

#pragma pack(1)
typedef struct {
    UINT8   Reserved[4];
    CHAR8   SerialNumber[20];
    // The rest of the 4096-byte structure is not used in this example.
} NVME_CONTROLLER_DATA;
#pragma pack()


VOID SBC_AntiTamperInit(VOID *priv)
{
    btctx = (boot_proc_t *)priv;
}

VOID SBC_AntiTamperDeinit(VOID *priv)
{

}
extern SBCStatus SBC_FileReadUnicodeSimple(
    IN  CHAR16    *FileName,
    OUT CHAR16  **OutBuffer,
    OUT UINTN     *OutLength
);

SBCStatus _find_kernel_path(CHAR16 **buf, UINTN *len_of_kernel)
{
    SBCStatus ret = SBCOK;

    ret = SBC_FileReadUnicodeSimple(KERNEL_DIR_FILE, buf, len_of_kernel);

    //SBC_mem_print_bin("Kernel path" , buf, *len_of_kernel);

    //dprint("kernel path : %s (count : %d )", (CHAR16 *)*buf, *len_of_kernel);

    return ret;

}

//SBCStatus _find_kernel_path(CHAR16 *fname)
//{
//
//    //UINT8 errmsg[512] = {0, };
//    SBCStatus ret = SBCOK;
//    UINTN               len_of_kernel = 0;
//    UINTN               hndlcnt;
//    EFI_HANDLE          *hndl;
//    UINTN               idx;
//    LV_t lv;
//    EFI_STATUS          Status;
//    CHAR8   *ascii_str;
//    UINTN x;
//
//    SBC_RET_VALIDATE_ERRCODEMSG((fname != NULL), SBCNULLP, "Object point to NILL");
//
//    ret = SBC_GetFileSize( KERNEL_DIR_FILE, &len_of_kernel);
//    SBC_RET_VALIDATE_ERRCODEMSG((ret == SBCOK), ret, "File Not Found");
//
//    hndlcnt = SBC_FindEfiFileSystemProtocol(&hndl);
//    if (hndlcnt <= 0) {
//        eprint("File System Handle find fail : %d", hndlcnt);
//        return SBCFAIL;
//    }
//
//    for (idx = 0; idx < hndlcnt; idx++) {
//        Status = SBC_IsFlieAccess(hndl[idx], KERNEL_DIR_FILE);
//        if (EFI_ERROR(Status)) {
//            continue;
//        }
//
//        break;
//    }
//
//    if (EFI_ERROR(Status)) {
//        eprint("%s  : %r", KERNEL_DIR_FILE, Status);
//        return SBCFAIL;
//    }
//
//    lv.value = AllocateZeroPool(len_of_kernel);
//    lv.length = len_of_kernel;
//    dprint("%s size %d", KERNEL_DIR_FILE, lv.length);
//    SBC_RET_VALIDATE_ERRCODEMSG((lv.value != NULL), SBCNULLP, "Out of Memory");
//
//    Status = SBC_ReadFile(hndl[idx], KERNEL_DIR_FILE, &lv);
//    if (EFI_ERROR(Status)) {
//        eprint("%s file read fail with %r", KERNEL_DIR_FILE, Status);
//        ret = SBCNOTFND;
//        goto errdone;
//    }
//
//    //AsciiStrToUnicodeStr(lv.value, fname);
//    //CopyMem((void *)fname, (const void *)lv.value, lv.length);
//    //fname[lv.length] = '\0';
//
//    // File name convert from Ascii to Unicode string
//    ascii_str = (CHAR8 *)lv.value;
//    SBC_mem_print_bin("Kernel Path", (UINT8 *)lv.value, lv.length );
//    //dprint("kernel name : %a", lv.value);
//    //ascii_str[lv.length] = '\0';
//    for ( x = 0;x < lv.length /* ascii_str[x] != '\0' */; x++) {
//        fname[x] = (CHAR16)ascii_str[x];
//    }
//
//    fname[x] = L'\0';
//
//errdone:
//
//    if (lv.value != NULL) {
//        FreePool(lv.value);
//        lv.value = NULL;
//    }
//
//    return ret;
//
//}


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

#if 0
SBCStatus SBC_EFI_SSBL_Load(VOID *blkhnd, LV_t *lv,  UINTN normbank, UINTN bm)
{

    SBCStatus           ret = SBCOK;
    UINTN               bsofs = 0; // Boot Sector Offset
    UINTN               startlba = 0;

    UINT32          imglen = SBC_RAWPRT_DFLT_BLK_SZ;
    UINT8           imghdr[SBC_RAWPRT_DFLT_BLK_SZ] = {0, };

    normbank++;


    if (bm != BOOT_MODE_FACTORY) {
      bsofs = (BOOT_SECTOR1_OFS | ((normbank - 1) << 20));
      startlba = ((bsofs | BOOT_SSBL_OFS) >> SBC_RAWPRT_DFLT_SHIFT);
    }
    else {
      bsofs = BOOT_SECTOR3_OFS;
      startlba = ((bsofs | BOOT_SSBL_OFS) >> SBC_RAWPRT_DFLT_SHIFT);
    }

    dprint("BSOFS:  0x%lx, StartLBA: %lu", bsofs, startlba);

    ret = SBC_RawPrtReadBlock(blkhnd, (void *)imghdr, &imglen, startlba);
    if (ret != SBCOK) {
        eprint("SSBL Factory Block Read Fail \n");
        goto errdone;
    }

    CopyMem((void *)&imglen, &imghdr[0], sizeof imglen);

    // If imglen is zero, assumed that image not existense in Raw partition
    if (imglen <= 0) {
      eprint("Boot Mode (%d) Image not existense", bm);
      ret = SBCZEROL;
      goto errdone;
    }
    //dprint("SSBL image len : %ld", imglen);
    imglen = ALIGN_VALUE(imglen, SBC_RAWPRT_DFLT_BLK_SZ);





    //dprint("Align SSBL image len : %ld", imglen);


    lv->value = AllocatePool(imglen);
    SBC_RET_VALIDATE_ERRCODEMSG((lv->value != NULL), SBCNULLP, "Allocate Memory Fail");

    ret = SBC_RawPrtReadBlock(blkhnd, (void *)lv->value, &imglen, startlba);
    SBC_RET_VALIDATE_ERRCODEMSG((ret == SBCOK), ret, "SSBL image read fail");


    lv->length = imglen - FSBL_BNIFO_SIZE;
    // skip the image header ( for Length )
    lv->value += 4;

errdone:

    return ret;

}
#else

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

#endif

#if 0
EFI_STATUS SBC_EFI_FSBL_Load(LV_t *lv)
{
  EFI_STATUS                          Status;
  EFI_HANDLE                          *HandleBuffer;
  UINTN                               NumberOfHandles;
  EFI_SIMPLE_FILE_SYSTEM_PROTOCOL     *SimpleFileSystem;
  EFI_FILE_PROTOCOL                   *RootFs = NULL;
  EFI_FILE_PROTOCOL                   *EfiDir = NULL;
  EFI_FILE_PROTOCOL                   *BootDir = NULL;
  EFI_FILE_PROTOCOL                   *X64File = NULL;
  EFI_FILE_INFO                       *FileInfo = NULL;
  UINTN                               FileInfoSize = 0;

  EFI_DEVICE_PATH_PROTOCOL *DevicePath = NULL;
//VOID                                *FileBuffer = NULL;
//UINTN                               FileSize = 0;

  // 1. Locate all Simple File System Protocol instances
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


  //Print(L"Number of Handles %d \n", NumberOfHandles);
  // Iterate through found file systems to find the one containing /EFI/BOOT/X64.efi
  // In a real scenario, you might have logic to identify the correct ESP.
  // For simplicity, we'll try the first one here.
  for (UINTN Index = 0; Index < NumberOfHandles; Index++) {

    DevicePath = FileDevicePath(HandleBuffer[Index], EFI_BOOT_FSBL_PATH);
    if (DevicePath == NULL) {
      eprint("FSBL Device path not found ");
      continue;
    }

    //dprint("Discover the device path for FSBL~~~");

    Status = gBS->HandleProtocol (
                    HandleBuffer[Index],
                    &gEfiSimpleFileSystemProtocolGuid,
                    (VOID **)&SimpleFileSystem
                    );
    if (EFI_ERROR (Status)) {
     dprint("Could not find a HandleProtocol file system.\n");
      continue;
    }

    // 2. Open the root volume
    Status = SimpleFileSystem->OpenVolume (
                                 SimpleFileSystem,
                                 &RootFs
                                 );
    if (!EFI_ERROR (Status)) {
      // Found a file system, try to open the EFI directory
      //break; // Exit loop, we found a potential file system
      //Print(L"Could not find a Open the root volume file system.\n");
      //return EFI_NOT_FOUND;
      break;
    }
  }

  if (RootFs == NULL) {
   dprint("Could not find a suitable file system.\n");
    gBS->FreePool(HandleBuffer);
    return EFI_NOT_FOUND;
  }

  // 3. Navigate to /EFI/BOOT/
  // Open EFI directory
  Status = RootFs->Open (
                     RootFs,
                     &EfiDir,
                     L"EFI",
                     EFI_FILE_MODE_READ,
                     0 // Attributes are 0 for directories
                     );
  if (EFI_ERROR (Status)) {
   dprint("Failed to open EFI directory: %r\n", Status);
    goto Exit;
  }

  // Open BOOT directory
  Status = EfiDir->Open (
                     EfiDir,
                     &BootDir,
                     L"BOOT",
                     EFI_FILE_MODE_READ,
                     0
                     );
  if (EFI_ERROR (Status)) {
   dprint("Failed to open BOOT directory: %r\n", Status);
    goto Exit;
  }

  // 4. Open X64.efi file
#ifndef _SSBL_TEST_
  Status = BootDir->Open (
                     BootDir,
                     &X64File,
                     L"bootx64.efi",
                     EFI_FILE_MODE_READ, // Open for reading
                     0 // Not creating, so attributes are 0
                     );
#else
  Status = BootDir->Open (
                     BootDir,
                     &X64File,
                     L"FSBL.efi",
                     EFI_FILE_MODE_READ, // Open for reading
                     0 // Not creating, so attributes are 0
                     );
#endif

  // 5. Get File Size
  FileInfoSize = 0;
  // First call to GetInfo to get the required buffer size
  Status = X64File->GetInfo (
                      X64File,
                      &gEfiFileInfoGuid,
                      &FileInfoSize,
                      NULL
                      );
  if (Status == EFI_BUFFER_TOO_SMALL) {
    Status = gBS->AllocatePool (
                    EfiBootServicesData,
                    FileInfoSize,
                    (VOID **)&FileInfo
                    );
    if (EFI_ERROR (Status)) {
     dprint("Failed to allocate memory for FileInfo: %r\n", Status);
      goto Exit;
    }
    // Second call to GetInfo to actually get the info
    Status = X64File->GetInfo (
                        X64File,
                        &gEfiFileInfoGuid,
                        &FileInfoSize,
                        FileInfo
                        );
  }
  if (EFI_ERROR (Status)) {
   dprint("Failed to get file info for X64.efi: %r\n", Status);
    goto Exit;
  }

  lv->length = FileInfo->FileSize;
  //Print(L"X64.efi file size: %lu bytes\n", lv->length);

  // 6. Read the File Contents
  Status = gBS->AllocatePool (
                  EfiBootServicesData,
                  lv->length,
                  (VOID **)&lv->value
                  );
  if (EFI_ERROR (Status)) {
   dprint("Failed to allocate memory for file buffer: %r\n", Status);
    goto Exit;
  }

  Status = X64File->Read (
                      X64File,
                      (UINTN *)&lv->length, // Pass pointer to size, it will be updated with bytes read
                      lv->value
                      );
  if (EFI_ERROR (Status)) {
   dprint("Failed to read X64.efi: %r\n", Status);
    goto Exit;
  }

  //Print(L"Successfully read X64.efi into memory at address 0x%lx. Read %lu bytes.\n", (UINTN)lv->value, lv->length);

  // At this point, FileBuffer contains the entire content of X64.efi
  // You can now process this buffer as needed (e.g., parse it, execute it, etc.)

Exit:
  // 7. Close File Handles and Free Resources
  if (FileInfo != NULL) {
    gBS->FreePool(FileInfo);
  }

  if (X64File != NULL) {
    X64File->Close(X64File);
  }
  if (BootDir != NULL) {
    BootDir->Close(BootDir);
  }
  if (EfiDir != NULL) {
    EfiDir->Close(EfiDir);
  }
  if (RootFs != NULL) {
    RootFs->Close(RootFs);
  }
  if (HandleBuffer != NULL) {
    gBS->FreePool(HandleBuffer);
  }

  return Status;
}
#endif



EFI_STATUS
OpenFileOnFsHandle(
  IN  EFI_HANDLE                       FsHandle,
  IN  CHAR16                          *AbsPath,
  OUT EFI_SIMPLE_FILE_SYSTEM_PROTOCOL **OutFs OPTIONAL,
  OUT EFI_FILE_PROTOCOL               **OutRoot,
  OUT EFI_FILE_PROTOCOL               **OutFile
  )
{
  if (OutRoot == NULL || OutFile == NULL || AbsPath == NULL)
    return EFI_INVALID_PARAMETER;

  EFI_STATUS Status;
  EFI_SIMPLE_FILE_SYSTEM_PROTOCOL *Fs = NULL;
  EFI_FILE_PROTOCOL *Root = NULL;
  EFI_FILE_PROTOCOL *File = NULL;

  Status = gBS->HandleProtocol(
                  FsHandle,
                  &gEfiSimpleFileSystemProtocolGuid,
                  (VOID**)&Fs
                  );
  if (EFI_ERROR(Status))
    return Status;

  Status = Fs->OpenVolume(Fs, &Root);
  if (EFI_ERROR(Status))
    return Status;

  Status = Root->Open(
                  Root,
                  &File,
                  AbsPath,
                  EFI_FILE_MODE_READ,
                  0
                  );
  if (EFI_ERROR(Status)) {
    Root->Close(Root);
    return Status;
  }

  if (OutFs)   *OutFs   = Fs;
  *OutRoot = Root;
  *OutFile = File;
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


/**
 * @fn SBC_EFI_FSBL_Load
 * @brief Load FSBL (or test image) from the EFI System Partition into memory.
 *
 * This function loads a target EFI binary from the same filesystem device
 * where the current image is loaded (typically ESP). The loaded content is
 * returned via @p lv (buffer pointer + length).
 *
 * Target file selection:
 * - Normal build: "\\EFI\\BOOT\\bootx64.efi"
 * - _SSBL_TEST_RUN_ build: "\\EFI\\BOOT\\FSBL.efi"
 *
 * @param[in,out] lv
 *      Pointer to LV_t output container.
 *      On success:
 *        - lv->value  points to newly allocated buffer containing file content
 *        - lv->length is set to file size in bytes
 *      On failure:
 *        - lv->value is NULL
 *        - lv->length is 0
 *
 * @retval EFI_SUCCESS
 *      File loaded successfully.
 *
 * @retval EFI_INVALID_PARAMETER
 *      @p lv is NULL.
 *
 * @retval EFI_OUT_OF_RESOURCES
 *      Memory allocation failed.
 *
 * @retval EFI_NOT_FOUND
 *      Failed to resolve LoadedImage protocol or filesystem device handle.
 *
 * @retval Others
 *      Propagated EFI_STATUS from underlying filesystem operations.
 *
 * @details
 * Processing steps:
 *
 * Step 1. Validate input parameter (<code>lv</code> != NULL). If invalid, return
 *         <code>EFI_INVALID_PARAMETER</code>.
 *
 * Step 2. Select the target file path depending on build option
 *         (<code>_SSBL_TEST_RUN_</code>).
 *
 * Step 3. Initialize output fields:
 *         <code>lv->value = NULL</code>, <code>lv->length = 0</code>.
 *
 * Step 4. Query the target file size using <code>GetFileSizeOnMyFs()</code>.
 *         If it fails, return the error status.
 *
 * Step 5. Allocate a buffer of <code>FileSize</code> bytes and set
 *         <code>lv->length = FileSize</code>. If allocation fails, return
 *         <code>EFI_OUT_OF_RESOURCES</code>.
 *
 * Step 6. Resolve <code>EFI_LOADED_IMAGE_PROTOCOL</code> from <code>gImageHandle</code>
 *         to obtain the filesystem device handle (<code>LoadedImage->DeviceHandle</code>).
 *         If not found, free the buffer, reset <code>lv</code>, and return
 *         <code>EFI_NOT_FOUND</code>.
 *
 * Step 7. Read the file content using the existing <code>SBC_ReadFile()</code>
 *         by passing <code>LoadedImage->DeviceHandle</code> (a handle that supports
 *         SimpleFS) and <code>TargetPath</code>.
 *         If read fails, free the buffer, reset <code>lv</code>, and return the error.
 *
 * Step 8. Return <code>EFI_SUCCESS</code> with <code>lv</code> containing the loaded image.
 *
 * @note
 * - The caller is responsible for freeing <code>lv->value</code> with <code>FreePool()</code>.
 * - This function intentionally passes <code>LoadedImage->DeviceHandle</code> to
 *   <code>SBC_ReadFile()</code> because <code>gImageHandle</code> usually does not have
 *   SimpleFS installed.
 */
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

SBCStatus  _read_fsbl_image(LV_t *lv)
{
    SBCStatus           ret = SBCOK;
    //UINT16              *fname = L"LeoTest.efi";
    EFI_HANDLE          handle = NULL;
    UINT16              *fsblid  = STRING_TOKEN(EFI_BOOT_FSBL_PATH);
    SBC_RET_VALIDATE_ERRCODEMSG((lv != NULL), SBCNULLP, "Output buffer is Nill");

    //Investigate file size
    ret = SBC_GetFileSize(fsblid, ((UINTN *)&lv->length));
    dprint("FSBL File Size : %d , Status : %d",  lv->length, ret);
    SBC_RET_VALIDATE_ERRCODEMSG(((ret != SBCFAIL) && (lv->length > 0)), ret, "FSBL F Size fail or File not found");


    //Allocate the File data buffer
    //It must release from caller
    lv->value = AllocateZeroPool((UINTN)lv->length);
    SBC_RET_VALIDATE_ERRCODEMSG((lv->value != NULL), SBCNULLP, "Output buffer create Nill");

    //Find the File handle protocol object
    SBC_FileSysFindHndl(&handle);
    SBC_RET_VALIDATE_ERRCODEMSG((handle != NULL), SBCNULLP, "Handle find fail");

    ret = SBC_ReadFile(handle, fsblid, lv);
    SBC_RET_VALIDATE_ERRCODEMSG((ret == SBCOK), ret, "FSBL read fail");


    //SBC_external_mem_print_bin((CHAR8 *)fsblid, lv->value, lv->length);

    return ret;

errdone:

    if (lv->value) {
        gBS->FreePool(lv->value);
        lv->value = NULL;
    }
    return ret;

}


SBCStatus _nvme_get_serial(hw_uniqueinfo_t *p)
{
    SBCStatus                 ret = SBCFAIL;
    EFI_STATUS                Status;
    EFI_HANDLE                *HandleBuffer;
    UINTN                     HandleCount;
    UINTN                     Index;
    EFI_NVM_EXPRESS_PASS_THRU_PROTOCOL *NvmePassThru;
    EFI_NVM_EXPRESS_COMMAND                   Command;
    EFI_NVM_EXPRESS_PASS_THRU_COMMAND_PACKET  CommandPacket;
    EFI_NVM_EXPRESS_COMPLETION                Completion;
    NVME_ADMIN_CONTROLLER_DATA                ControllerData;


    // Locate handles that support the NVMe Pass Thru Protocol.
    Status = gBS->LocateHandleBuffer(
                        ByProtocol,
                        &gEfiNvmExpressPassThruProtocolGuid,
                        NULL,
                        &HandleCount,
                        &HandleBuffer);
    if (EFI_ERROR(Status)) {
       dprint("Error: No NVMe devices found - %r\n", Status);
        ret = SBCFAIL;
        goto errdone;
    }

    //Print(L"Found %u NVMe device(s).\n", HandleCount);

    for (Index = 0; Index < HandleCount; Index++) {
        // Get the NVMe Pass Thru Protocol from the current handle.
        Status = gBS->HandleProtocol(
                           HandleBuffer[Index],
                           &gEfiNvmExpressPassThruProtocolGuid,
                           (VOID**)&NvmePassThru);
        if (EFI_ERROR(Status)) {
           dprint("Error: Could not access NVMe Pass Thru on device %u - %r\n", Index, Status);
            continue;
        }

        // Allocate a buffer for the NVMe Identify Controller data.
        // The Identify Controller data is 4096 bytes.
        UINT32 BufferSize = 4096;
        VOID *Buffer = AllocatePool(BufferSize);
        if (Buffer == NULL) {
           dprint("Error: Failed to allocate memory for device %u\n", Index);
            continue;
        }
        SetMem(Buffer, BufferSize, 0);

        // Prepare the NVMe Identify Controller command.
        // Opcode 0x06 is the Identify command. Setting NSID to 0 indicates we want controller data.
        // The lower 8 bits of Cdw10 (called CNS) must be set to 1 for Identify Controller.

        ZeroMem (&CommandPacket, sizeof (EFI_NVM_EXPRESS_PASS_THRU_COMMAND_PACKET));
        ZeroMem (&Command, sizeof (EFI_NVM_EXPRESS_COMMAND));
        ZeroMem (&Completion, sizeof (EFI_NVM_EXPRESS_COMPLETION));

        //Command.Cdw0.Opcode = 0x06; // Identify Command opcode
        Command.Cdw0.Opcode = NVME_ADMIN_IDENTIFY_CMD;
        Command.Nsid = 0;
        Command.Cdw10 = 1;    // CNS = 1 ---> Identify controller.
        CommandPacket.NvmeCmd        = &Command;
        CommandPacket.NvmeCompletion = &Completion;
        CommandPacket.TransferBuffer = &ControllerData;
        CommandPacket.TransferLength = sizeof (ControllerData);
        CommandPacket.CommandTimeout = EFI_TIMER_PERIOD_SECONDS (5);
        CommandPacket.QueueType      = NVME_ADMIN_QUEUE;


                //
        // Set bit 0 (Cns bit) to 1 to identify a controller
        //
        Command.Cdw10 = 1;
        Command.Flags = CDW10_VALID;
        Status = NvmePassThru->PassThru(
                       NvmePassThru,
                       0,           // NamespaceId is 0 for controller command.
                       &CommandPacket,
                       NULL);
        if (EFI_ERROR(Status)) {
           dprint("Error: NVMe Identify command failed on device %u - %r\n", Index, Status);
            FreePool(Buffer);
            continue;
        }

        // Interpret the buffer as NVME_CONTROLLER_DATA.
        NVME_CONTROLLER_DATA *nvme_ctrldata =
            (NVME_CONTROLLER_DATA *)CommandPacket.TransferBuffer;

        //NVME_CONTROLLER_DATA *ControllerData = (NVME_CONTROLLER_DATA *)Buffer;

        // Copy the 20-byte serial number into a local buffer and null-terminate it.
        CHAR8 Serial[21];
        CopyMem(Serial, nvme_ctrldata->SerialNumber, 20);
        Serial[20] = '\0';

        // Trim trailing spaces from the serial number.
        for (INTN i = 19; i >= 0; i--) {
            if (Serial[i] == ' ')
                Serial[i] = '\0';
            else
                break;
        }

       //dprint("NVMe Device %u Serial Number: %a\n", Index, Serial);
        //SBC_mem_print_bin("NVME DEV SN", (UINT8 *)Serial, 32);
        p->nvmesnl = strlen(Serial);
        CopyMem(p->nvmesn, Serial, p->nvmesnl);
        FreePool(Buffer);
        break;
    }

    ret = SBCOK;
errdone:
    if (HandleBuffer) {
        FreePool(HandleBuffer);
    }
    return ret;
}

static SBCStatus _baseboard_sn(hw_uniqueinfo_t *p)
{
    SBCStatus ret = SBCFAIL;
    EFI_SMBIOS_PROTOCOL *Smbios;
    EFI_STATUS Status;
    EFI_SMBIOS_HANDLE SmbiosHandle = SMBIOS_HANDLE_PI_RESERVED;
    SMBIOS_TABLE_TYPE2 *Type2Record; // Base Board Information
    EFI_SMBIOS_TABLE_HEADER *Record;
    UINT32 cnt = 0;


    SBC_RET_VALIDATE_ERRCODEMSG((p != NULL), SBCNULLP, "HW structure NIll");

    Status = gBS->LocateProtocol(&gEfiSmbiosProtocolGuid, NULL, (VOID **)&Smbios);
    SBC_RET_VALIDATE_ERRCODEMSG((Status == EFI_SUCCESS), SBCPROTO, "Smbiod Protocol Not found");

    p->mmsnl = 0;
    while(!EFI_ERROR((Status = Smbios->GetNext(Smbios, &SmbiosHandle, NULL, &Record, NULL)))) {
        //dprint("Record->Type : %d\n", Record->Type);
        if(Record->Type == SMBIOS_TYPE_BASEBOARD_INFORMATION) {

            Type2Record = (SMBIOS_TABLE_TYPE2 *)Record;
            // Extract Serial Number (this is an index into the string table)
            UINT8 SerialNumberIndex = Type2Record->SerialNumber;
            //UINT8 SerialNumberIndex = Type2Record->Manufacturer;
            //CHAR8 *SerialNumberString = (CHAR8 *)(Record);
            CHAR8 *SerialNumberString = (((CHAR8 *)Record) + Record->Length);
            //SBC_external_mem_print_bin("_baseboard record", (UINT8 *)SerialNumberString, 0x79 - Record->Length);
            //dprint("serial number index : %d (Record Length : 0x%x)",
            //       SerialNumberIndex, Record->Length);
            if (SerialNumberIndex > 0) {
#if 0
                for (UINT8 i = 1; i < SerialNumberIndex; i++) {

                    while (*SerialNumberString != '\0') {
                        //p->mbsn[p->mbsnl++] = *SerialNumberString;
                        SerialNumberString++;
                        cnt++;
                    }
                    SerialNumberString++;
                    cnt++;
                }

#else

                for (UINT16 Index = 1; Index <= SerialNumberIndex; Index++) {
                    if (SerialNumberIndex == Index) {
                        break;
                    }

                    // Skip String
                    for (; *SerialNumberString != 0; SerialNumberString++) {
                    }

                    SerialNumberString++;
                    if (*SerialNumberString == 0) {
                        SBC_mem_print_bin("_baseboard_sn pass", (UINT8 *)SerialNumberString, p->mbsnl);
                    }
                    cnt++;
                }
#endif
                p->mbsnl = strlen(SerialNumberString);
                //SBC_external_mem_print_bin("_baseboard_sn", (UINT8 *)SerialNumberString, p->mbsnl);
                CopyMem(p->mbsn, SerialNumberString, p->mbsnl);


            }
        }
    }
    ret = SBCOK;

errdone:

    return ret;
}

static SBCStatus _memorydevice_sn(hw_uniqueinfo_t *p)
{
    SBCStatus ret = SBCFAIL;
    EFI_SMBIOS_PROTOCOL *Smbios;
    EFI_STATUS Status;
    EFI_SMBIOS_HANDLE SmbiosHandle = SMBIOS_HANDLE_PI_RESERVED;
    SMBIOS_TABLE_TYPE17 *Type2Record; // Base Board Information
    EFI_SMBIOS_TABLE_HEADER *Record;
    UINT32 cnt = 0;


    SBC_RET_VALIDATE_ERRCODEMSG((p != NULL), SBCNULLP, "HW structure NIll");

    Status = gBS->LocateProtocol(&gEfiSmbiosProtocolGuid, NULL, (VOID **)&Smbios);
    SBC_RET_VALIDATE_ERRCODEMSG((Status == EFI_SUCCESS), SBCPROTO, "Smbiod Protocol Not found");

    p->mmsnl = 0;
    while(!EFI_ERROR((Status = Smbios->GetNext(Smbios, &SmbiosHandle, NULL, &Record, NULL)))) {
        //dprint("Record->Type : %d\n", Record->Type);
        if(Record->Type == SMBIOS_TYPE_MEMORY_DEVICE) {

            Type2Record = (SMBIOS_TABLE_TYPE17 *)Record;
            // Extract Serial Number (this is an index into the string table)
            UINT8 SerialNumberIndex = Type2Record->SerialNumber;
            //dprint("serial number index : %d", SerialNumberIndex);
            CHAR8 *SerialNumberString = (((CHAR8 *)Record) + Record->Length);
            //SBC_external_mem_print_bin("_memorydevice_sn record", (UINT8 *)SerialNumberString, 0x8B -  Record->Length);
            if (SerialNumberIndex > 0) {
#if 0
                for (UINT8 i = 1; i < SerialNumberIndex; i++) {

                    while (*SerialNumberString != '\0') {
                        //p->mbsn[p->mbsnl++] = *SerialNumberString;
                        SerialNumberString++;
                        cnt++;
                    }
                    SerialNumberString++;
                    cnt++;
                }

#else

                for (UINT16 Index = 1; Index <= SerialNumberIndex; Index++) {
                    if (SerialNumberIndex == Index ) {
                        break;
                    }

                    // Skip String
                    for (; *SerialNumberString != 0; SerialNumberString++);

                    SerialNumberString++;
                    if (*SerialNumberString == 0) {
                       dprint("f you pass in a -1 you will always get here\n");
                    }
                    cnt++;
                }
#endif
               //dprint("_memorydevice_sn Serial Number: %a (%d)\n",
                //      SerialNumberString,cnt);
                p->mmsnl = strlen(SerialNumberString);
                CopyMem(p->mmsn, SerialNumberString, p->mmsnl);
                //SBC_mem_print_bin("_memorydevice_sn", (UINT8 *)p->mmsn, p->mmsnl);

            }
        }
    }
    ret = SBCOK;

errdone:

    return ret;
}


SBCStatus  SBC_BaseAnswerStore(VOID *blkio, VOID *p)
{
    SBCStatus ret = SBCOK;

    //VOID *blkio = NULL;
    base_ansid_t *h = NULL;
    UINT8 *loadbuf;
    UINT8 *cpy = NULL;
    UINT32 ldlen = BASE_ANS_BLK_LEN;
    UINTN baseansr_lba = 0;

#ifdef _TEST_ERROR_SET_    
    if (NvramErr_IsTrue(ERR_BASEANSWR_WRITE)) {
        sbc_err_sysprn(SBC_LOG_CMN_PRIO_INFO, 2,
                 SYS_LOG_HOST_BOOT,
                 SYS_LOG_APP_NAME,
                 SYS_LOG_CSC_NAME,
                 0,
                 SYS_LOG_EVT_DETECTION,
                 L"SBC_VENDOR_SP Fail to the Base answer storing");
        ret = SBCFAIL;
        goto errdone;
    }
#endif

    h = (base_ansid_t *)p;
    
    SBC_RET_VALIDATE_ERRCODEMSG((p != NULL), SBCNULLP, "Base-answer Invalid object");
    SBC_RET_VALIDATE_ERRCODEMSG((blkio != NULL), SBCNULLP, "Block I/O Invalid object");


    baseansr_lba = (SYS_CONF_START_OFS >> SBC_RAWPRT_DFLT_SHIFT);
    ldlen = ALIGN_VALUE(SYS_SETTING_STORAGE_LEN, ((EFI_BLOCK_IO_PROTOCOL *)blkio)->Media->BlockSize);
    loadbuf = AllocateZeroPool(ldlen);
    SBC_RET_VALIDATE_ERRCODEMSG((loadbuf != NULL), SBCNULLP, "Buffer invalid object");

    ret = SBC_RawPrtReadBlock(blkio, 
                              (VOID *)loadbuf, 
                              &ldlen, 
                              baseansr_lba);
    if (ret != SBCOK) {
       dprint("SBC_RawPrtReadBlock fail (%p)\n", blkio);
        goto errdone;
    }

//  SBC_external_mem_print_bin("Before Base Ans write",
//                             (UINT8 *)&loadbuf[SYS_CONF_RES_OFS],
//                             64);

    // TODO : Fill up the Base Answer in RAM buffer 
    cpy = (UINT8 *)&loadbuf[SYS_CONF_RES_OFS];
    CopyMem((void *)cpy, &h->msglen, sizeof h->msglen);
    //dprint("Message Len : %d", h->msglen);
    cpy += sizeof h->msglen;

    CopyMem((void *)cpy, h->encmsg, h->msglen );
    cpy += h->msglen;

    CopyMem((void *)cpy, h->iv, BASE_ANS_IV_KEY_STR);
    cpy += BASE_ANS_IV_KEY_STR;

    CopyMem((void *)cpy, h->tag, BASE_ANS_TAG_LEN);
    cpy += BASE_ANS_TAG_LEN;

    ZeroMem((void *)cpy, 16); // Reserved  bytes set to zero
//  SBC_external_mem_print_bin("After Base Ans write",
//                             (UINT8 *)&loadbuf[SYS_CONF_RES_OFS],
//                             64);



    ret = SBC_RawPrtBlockWrite(blkio, loadbuf, ldlen, baseansr_lba);
    if (ret != SBCOK) {
      //Print(L"SBC Raw Partition Base Answer write fail \n");
      goto errdone;
    }


#ifdef _TEST_BED_
    {
        UINT8 temp[64] = {0, };
        
        dprint("*** 5.3.6.1 6.OSID Encrypt Data --->");
        SBC_BlkReadArbitrary(blkio, 
                             SYS_CONF_START_OFS + SYS_CONF_RES_OFS,
                             (VOID *)temp,
                             64);

        SBC_mem_print_bin("OSID Encrypt Read", temp, 64);
    }

#endif
    ret = SBCOK;

errdone:
    if (loadbuf != NULL) {
      FreePool(loadbuf);
    }
    return ret;

}

/**
 * @fn SBC_BaseAnswerExtractFromDisk
 * @brief Extract Base Answer data from raw system configuration partition.
 *
 * This function reads the system configuration storage region from disk and
 * extracts Base Answer fields from the reserved response offset area.
 *
 * @param[in]  blkio
 *      Block I/O protocol handle for raw partition access.
 *
 * @param[out] p
 *      Pointer to base_ansid_t structure to receive:
 *      - msglen : encrypted message length
 *      - encmsg : encrypted message payload
 *      - iv     : AES-GCM IV
 *      - tag    : AES-GCM authentication tag
 *
 * @retval SBCOK
 *      Extraction succeeded.
 *
 * @retval SBCNULLP
 *      Invalid parameter or allocation failure.
 *
 * @retval SBCFAIL
 *      Forced failure in test mode or underlying read error.
 *
 * @retval SBCBSANSWNOTFND
 *      Base Answer not found (msglen <= 0).
 *
 * @details
 * Processing steps:
 *
 * Step 1. Validate output parameter (<code>p</code> != NULL).
 *
 * Step 2. Calculate the base LBA of the system configuration storage
 *         using <code>SYS_CONF_START_OFS</code>.
 *
 * Step 3. Align the storage length to the block size reported by
 *         <code>EFI_BLOCK_IO_PROTOCOL</code>.
 *
 * Step 4. Allocate a zero-initialized temporary buffer for the read operation.
 *
 * Step 5. Read the system configuration data block from the raw partition
 *         into the temporary buffer.
 *
 * Step 6. Set <code>offset</code> to the reserved response offset
 *         (<code>SYS_CONF_RES_OFS</code>).
 *
 * Step 7. Extract Base Answer message length (<code>msglen</code>) from the buffer
 *         and validate it is greater than 0. If not, return <code>SBCBSANSWNOTFND</code>.
 *
 * Step 8. Extract encrypted message (<code>encmsg</code>) using <code>msglen</code>.
 *
 * Step 9. Extract AES-GCM IV (<code>iv</code>) with length <code>BASE_ANS_IV_KEY_STR</code>.
 *
 * Step 10. Extract AES-GCM authentication tag (<code>tag</code>) with length
 *          <code>BASE_ANS_TAG_LEN</code>.
 *
 * Step 11. Return status (caller owns <code>p</code> and must ensure its internal
 *          buffers are large enough).
 *
 * @note
 * - Caller must ensure <code>p->encmsg</code> buffer capacity is >= stored msglen.
 * - This function currently does not FreePool(loadbuf); consider releasing it
 *   to avoid memory leaks in long-running contexts.
 */
static SBCStatus SBC_BaseAnswerExtractFromDisk(VOID *blkio, base_ansid_t *p)
{
  SBCStatus ret = SBCOK;

  UINT8 *loadbuf;
  UINT32 ldlen = BASE_ANS_BLK_LEN;
  UINTN baseansr_lba = 0;
  UINTN offset = 0;

#ifdef _TEST_ERROR_SET_    
    if (NvramErr_IsTrue(ERR_BASEANSWR_READ)) {
        sbc_err_sysprn(SBC_LOG_CMN_PRIO_INFO, 2,
                 SYS_LOG_HOST_BOOT,
                 SYS_LOG_APP_NAME,
                 SYS_LOG_CSC_NAME,
                 0,
                 SYS_LOG_EVT_DETECTION,
                 L"SBC_VENDOR_SP Fail to the Base answer read");
        ret = SBCFAIL;
        goto errdone;
    }
#endif

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
  CopyMem((void *)&p->msglen, (void *)&loadbuf[offset], 4);
  SBC_RET_VALIDATE_ERRCODEMSG((p->msglen > 0), SBCBSANSWNOTFND, "Base Answer Not Foudn");
  offset += 4;

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


//dprint("Enc Msg Len : %d", p->msglen);
//SBC_mem_print_bin("Base ANswer Enc Message", p->encmsg, p->msglen);
//SBC_mem_print_bin("Enc IV", p->iv, BASE_ANS_IV_KEY_STR);
//SBC_mem_print_bin("Tag Message", p->tag, BASE_ANS_TAG_LEN);
  

errdone:
  return ret;
}

SBCStatus SBC_ProtectedSWEnc(VOID *priv)
{
    SBCStatus ret = SBCOK;
    boot_proc_t *p = (boot_proc_t *)priv;

    SBC_RET_VALIDATE_ERRCODEMSG((p != NULL),
                                SBCNULLP,
                                "Invalid Argument");


errdone:

    return ret;
}

SBCStatus SBC_DeviceSecuirtyKeyCreate(VOID *key)
{
    SBCStatus ret = SBCOK;
    hw_uniqueinfo_t info;
    UINT8 *computebuf = NULL;
    UINTN cnt = 0;
    UINTN   allocate_len = 0;

#ifdef _TEST_ERROR_SET_    
    if (NvramErr_IsTrue(ERR_SECKEY_CREATE)) {
        sbc_err_sysprn(SBC_LOG_CMN_PRIO_INFO, 2,
                     SYS_LOG_HOST_BOOT,
                     SYS_LOG_APP_NAME,
                     SYS_LOG_CSC_NAME,
                     0,
                     SYS_LOG_EVT_DETECTION,
                     L"SBC_VENDOR_SP Fail to Genearte the Device Security Key ");
        ret = SBCFAIL;

        goto errdone;
    }
#endif

    SBC_RET_VALIDATE_ERRCODEMSG((key != NULL), SBCNULLP, "Output Nill");

    _baseboard_sn(&info);
    _memorydevice_sn(&info);
    _nvme_get_serial(&info);


    allocate_len = info.mbsnl + info.mmsnl + info.nvmesnl;
    computebuf = AllocatePool(allocate_len);
    SBC_RET_VALIDATE_ERRCODEMSG((computebuf != NULL),
                                SBCNULLP, 
                                "Blob buffer Nill");

    cnt = 0;
     //Print(L" cnt : %d \n", cnt);
    CopyMem((void *)&computebuf[0], info.mbsn, info.mbsnl);
    cnt = info.mbsnl;

     //Print(L"Next cnt : %d \n", cnt);
    CopyMem((void *)&computebuf[cnt], info.mmsn, info.mmsnl);
    cnt += info.mmsnl;

     //Print(L"Next Next cnt : %d \n", cnt);
    CopyMem((void *)&computebuf[cnt], info.nvmesn, info.nvmesnl);
    cnt += info.nvmesnl;

    dprint("Security Key Message : %a", computebuf);
    

    ret = SBC_HashCompute(NULL,
                          computebuf, 
                          32,
                          key);


    //SBC_external_mem_print_bin("Security Key", key, 32);
    if (ret != SBCOK) {
    
        sbc_err_sysprn(SBC_LOG_CMN_PRIO_ERR, 2,
                     SYS_LOG_HOST_BOOT,
                     SYS_LOG_APP_NAME,
                     SYS_LOG_CSC_NAME,
                     1,
                     SYS_LOG_EVT_DETECTION,
                     L"SBC_RawFS_Key Failed the security key create \n"
                    );

        goto errdone;
    }

    SBC_BuildHexFormattedMessage(
                (CONST VOID *)computebuf, 32,
                L"SBC_RawFS_Key Create security key  (%s)\n",
                mrgmsg, sizeof mrgmsg);

    sbc_err_sysprn(SBC_LOG_CMN_PRIO_INFO, 2,
                  SYS_LOG_HOST_BOOT,
                  SYS_LOG_APP_NAME,
                  SYS_LOG_CSC_NAME,
                  1,
                  L"Validation",
                  mrgmsg);


errdone:

    return ret;

}


SBCStatus  SBC_FirmwareIdKyeVerify(VOID *priv)
{
    boot_proc_t *bp = NULL;
    SBCStatus ret = SBCOK;
    at_key_t key_pair;
    at_key_t rcv_key_pair;

    VOID *ctx = NULL;
    BOOLEAN retval;

    UINT8 pubkey[64] = {0,};
    UINTN pubkeyl = 0;
    UINT8 *loadbuf;
    UINT32 ldlen = BASE_ANS_BLK_LEN;
    UINTN systm_lba = 0;
    SBC_AESGcmCtx  decctx;
    SBC_AESContext  aesctx;

    UINTN offset = 0;
    UINTN calen = 0;

    UINT8 decbuf[2048] = {0,};
    UINT8 secret_key[SYS_OSID_KEY_LEN] = {0, };

    VOID *blkio = NULL;
    VOID *fwid = NULL;

    //BOOL  b_verifypass = FALSE;

    dprint("Starting !!!");

    bp = (boot_proc_t *)priv;

    blkio = bp->blkhnd;
    fwid = ((atp_ident_t *)bp->keyinfo)->fwid;


    // Generate the Public Key
    ret = SBC_DICESeedKeyPair(fwid, &key_pair);
    SBC_RET_VALIDATE_ERRCODEMSG((ret == SBCOK), SBCINVPARAM, "Firmware ID Key-pair gen fail");

    SBC_external_mem_print_bin("Org. Priv", key_pair.d, sizeof key_pair.d);
    SBC_external_mem_print_bin("Org. Pub", key_pair.q.value , sizeof key_pair.q);

    // Device ID certificate Load 
    systm_lba = (SYS_CONF_START_OFS >> SBC_RAWPRT_DFLT_SHIFT);
    dprint("Sys Conf offset (402653696) %d", SYS_CONF_START_OFS);
    dprint("System Setting Start LBA (768433) : %lu (0x%lx)", systm_lba, systm_lba);
    ldlen = ALIGN_VALUE(SYS_SETTING_STORAGE_LEN, ((EFI_BLOCK_IO_PROTOCOL *)blkio)->Media->BlockSize);
    loadbuf = AllocateZeroPool(ldlen);
    SBC_RET_VALIDATE_ERRCODEMSG((loadbuf != NULL), SBCNULLP, "Buffer invalid object");

    ret = SBC_RawPrtReadBlock(blkio, 
                              (VOID *)loadbuf, 
                              &ldlen, 
                              systm_lba);
    if (ret != SBCOK) {
       dprint("SBC_RawPrtReadBlock fail (%p)\n", blkio);
        goto errdone;
    }

    //SBC_mem_print_bin("12 Device ID cert", (UINT8 *)loadbuf, ldlen);
#if 1 //ndef _SSBL_TEST_ 
    offset = SYS_CONF_FWID_CRT_OFS;
#else

    UINT8 rawData[428] = {                                           
    	0x8C, 0x01, 0x00, 0x00, 0xD9, 0xFA, 0xCB, 0x23, 0x89, 0xBA, 0xE4, 0x9A,
    	0xCB, 0x75, 0xB2, 0x8B, 0x3D, 0xC2, 0x5C, 0x9E, 0xA7, 0xF2, 0x94, 0x66,
    	0x70, 0x22, 0x4A, 0xDF, 0x2D, 0x70, 0x36, 0xAB, 0xA7, 0x6C, 0xE0, 0xC3,
    	0x3D, 0xDD, 0xB4, 0xBD, 0x85, 0xD0, 0x86, 0xC4, 0x53, 0x2F, 0xBE, 0x7E,
    	0x73, 0x83, 0x23, 0x0B, 0x15, 0xA5, 0x65, 0xE3, 0xB0, 0x84, 0x0A, 0x4A,
    	0x3F, 0xC6, 0xED, 0xD7, 0xED, 0x5A, 0x5A, 0x53, 0x80, 0xA8, 0xAB, 0x02,
    	0xA2, 0xE8, 0x48, 0x4D, 0x4C, 0x2E, 0x27, 0x5D, 0xF8, 0xF3, 0xAC, 0x06,
    	0x21, 0xFE, 0xA4, 0x7F, 0xE6, 0x2A, 0x4D, 0xC9, 0x7B, 0x73, 0x33, 0xEF,
    	0xB3, 0xD8, 0x6E, 0xA7, 0xB4, 0x4C, 0xD4, 0xB5, 0x5E, 0x06, 0xA4, 0x87,
    	0xCF, 0x44, 0xA0, 0xE1, 0x6F, 0x00, 0x62, 0xA5, 0xC1, 0x51, 0x27, 0x89,
    	0xD0, 0xFF, 0x40, 0x56, 0xAF, 0x29, 0x57, 0x45, 0x22, 0x3B, 0x2A, 0xE1,
    	0xBF, 0x32, 0x59, 0x05, 0xC3, 0x05, 0x19, 0x62, 0x9D, 0x79, 0x56, 0x70,
    	0xDC, 0x30, 0xE0, 0xFE, 0x5F, 0x1D, 0x2F, 0xB8, 0x16, 0x71, 0x3B, 0x2B,
    	0x03, 0x8A, 0x0B, 0x29, 0x67, 0x97, 0x42, 0x08, 0x0D, 0x9D, 0xD0, 0x20,
    	0xE1, 0x80, 0x0A, 0x29, 0xE3, 0xC7, 0x46, 0x2C, 0xFE, 0xC3, 0xC0, 0x81,
    	0xC9, 0x33, 0x3F, 0x81, 0xAC, 0x7D, 0x9A, 0xC2, 0xBE, 0x8A, 0x4E, 0xD1,
    	0x76, 0xFB, 0x25, 0xB3, 0x07, 0x17, 0x08, 0x5B, 0x5C, 0x67, 0x06, 0xDB,
    	0x02, 0xF5, 0xFC, 0x09, 0x10, 0xD4, 0x06, 0xB9, 0xAD, 0xAE, 0x4F, 0xF7,
    	0x16, 0x80, 0x7F, 0x21, 0x0A, 0x56, 0x48, 0xA1, 0x32, 0x69, 0xA9, 0xDB,
    	0x52, 0x5B, 0x43, 0x87, 0xBD, 0x08, 0x8E, 0x06, 0x91, 0x88, 0x9E, 0x66,
    	0x82, 0x47, 0x6B, 0x69, 0xE7, 0x12, 0x9A, 0xDE, 0xB9, 0x61, 0x2F, 0xE3,
    	0xDC, 0x71, 0x8E, 0x61, 0xE9, 0x5A, 0x8E, 0x17, 0x90, 0xBF, 0x35, 0x9B,
    	0x4D, 0x16, 0xAF, 0x72, 0x16, 0x54, 0x0D, 0xA6, 0xCD, 0x0A, 0xFF, 0x76,
    	0xB8, 0x49, 0x0C, 0xF2, 0x8E, 0x29, 0x04, 0x77, 0x43, 0x5C, 0x69, 0x83,
    	0x34, 0xA8, 0xA4, 0x6B, 0xD6, 0x52, 0x8A, 0x93, 0x2D, 0x23, 0x46, 0x8F,
    	0xBD, 0x08, 0x84, 0x2C, 0x3F, 0xA5, 0x52, 0x5B, 0x90, 0x75, 0x10, 0xF7,
    	0xF6, 0x93, 0x97, 0x89, 0xA9, 0xC1, 0x41, 0x6A, 0xD9, 0xA2, 0xC0, 0x9A,
    	0x3D, 0xDB, 0x41, 0x00, 0xA3, 0x8D, 0x89, 0xCD, 0x41, 0x71, 0x7B, 0x31,
    	0xE6, 0x90, 0x5A, 0x9D, 0x33, 0x79, 0x02, 0xC6, 0xDD, 0xB0, 0x49, 0x96,
    	0x92, 0xD5, 0xE6, 0xD9, 0xE5, 0x4C, 0x8D, 0xC8, 0x0C, 0x8C, 0x7F, 0x0D,
    	0xEA, 0x7B, 0xD4, 0xA2, 0x52, 0xC2, 0x95, 0x81, 0x5B, 0x11, 0xFB, 0x6D,
    	0x75, 0x9F, 0xD8, 0xEE, 0x0E, 0x19, 0x5A, 0xFE, 0xA0, 0xC2, 0x3D, 0x01,
    	0x80, 0x38, 0xBF, 0xC2, 0xBC, 0x8A, 0xAA, 0x30, 0x47, 0xC6, 0x34, 0x8B,
    	0x16, 0x62, 0x7D, 0x39, 0x46, 0x66, 0x58, 0x8C, 0x75, 0x4B, 0x37, 0x87,
    	0xCE, 0x53, 0x4A, 0x35, 0xEE, 0x9B, 0x9E, 0x30, 0xF2, 0xD3, 0xB4, 0xA5,
    	0x85, 0x85, 0xF8, 0x2B, 0x90, 0xB4, 0xFE, 0xF7                         
    };                                                                       

    loadbuf = rawData;
    offset = 0;
#endif

    CopyMem((void *)&calen, (void *)&loadbuf[offset], 4);

    dprint("Firmware ID CA Len : %d ", calen);
    offset += 4;
    // Decrypt 

    SBC_mem_print_bin("Firmware ID cert", (UINT8 *)&loadbuf[offset], calen);

    decctx.msg.value = &loadbuf[offset];
    decctx.msg.length = calen;

    offset += calen;
    decctx.iv.value = &loadbuf[offset];
    decctx.iv.length = BASE_ANS_IV_KEY_STR;
    SBC_mem_print_bin("Firmware ID IV", (UINT8 *)&loadbuf[offset], BASE_ANS_IV_KEY_STR);

    
    offset += BASE_ANS_IV_KEY_STR;
    decctx.tag.value = &loadbuf[offset];
    decctx.tag.length = BASE_ANS_TAG_LEN;
    SBC_mem_print_bin("Firmware ID TAG", (UINT8 *)&loadbuf[offset], BASE_ANS_TAG_LEN);

#ifdef _SSBL_TEST_
    UINTN idx = 0;

    for (idx = 0; idx < 32; idx++)
        secret_key[idx] = idx + 20;
#else
    // Device Secret Key Create 
    ret = SBC_DeviceSecuirtyKeyCreate(secret_key);
    SBC_RET_VALIDATE_ERRCODEMSG((ret == SBCOK), 
                                SBCINVPARAM, 
                                "Firmware ID Key-pair gen fail");

#endif
    //SBC_mem_print_bin("FW Secert Key", secret_key, BASE_ANS_KEY_STR);
    decctx.key.value = secret_key;
    decctx.key.length = BASE_ANS_KEY_STR;
    //SBC_mem_print_bin("Dec Key", (UINT8 *)deckey, BASE_ANS_KEY_STR);

    decctx.aad.value = NULL;
    decctx.aad.length = 0;

    decctx.out.value = decbuf;
    decctx.out.length = calen;

    aesctx.gcm = &decctx;
    aesctx.algoid = SBC_CIPHER_AES_GCM;

    if (SBC_AESGcmDecrypt(&aesctx) != SBCOK) {
        eprint("FW CA decrypt fail");
        ret = SBCDECFAIL;
        goto errdone;
    }

    SBC_mem_print_bin("Decrypt FW ID cert", (UINT8 *)decbuf, calen);

    if (((rawprt_hdr_t *)bp->rawprt_hdr)->rcvmode/* && (bp->bm == BOOT_MODE_NORMAL) */) {
        
        // Key Pair compare 
        dprint("Firmware ID verify, Boot Mode is NORMAL and it's run from Recovery Mode");

        //TODO 
        //A. Private and Public Key extract from Buffer.
        //ret = SBC_DICESeedKeyPair(fwid, &rcv_key_pair);
        //B. Public Key compute using Private Key.

        CopyMem(&rcv_key_pair, decbuf, calen);
        CopyMem(pubkey, rcv_key_pair.q.value, sizeof rcv_key_pair.q.value); 
        pubkeyl = sizeof rcv_key_pair.q.value;

        //b_verifypass = TRUE;
    }
    else {

        // Get Public Key
        ret = SBC_EcGetPublicKeyFromPem((CONST UINT8 *)decbuf, calen, &ctx);
        SBC_RET_VALIDATE_ERRCODEMSG((ret == SBCOK), SBCINVPARAM, "Public key extract fail");

        pubkeyl = ATP_IDENT_KEY_STG * 2;
        retval = EcGetPubKey(ctx, pubkey, &pubkeyl);
        if(retval != TRUE) {
            ret = SBCFAIL;
            eprint("EcGetPubKey fail %d", retval);
            goto errdone;
        }
    }

#ifdef _SSBL_TEST_
    SBC_external_mem_print_bin("Certificate Pubkey", pubkey, pubkeyl);
    dprint("PublicK Key Match Done ...");

#else
    SBC_external_mem_print_bin("Certificate Pubkey", pubkey, pubkeyl);
    SBC_external_mem_print_bin("FirmwareId ID Pubkey", key_pair.q.value, key_pair.ql);
    if(CompareMem(key_pair.q.value,  pubkey, pubkeyl) != 0) {
        SBC_BuildHexFormattedMessage(
            (CONST VOID *)pubkey, (UINTN)pubkeyl,
            L"SBC_Dice_Verify Failed to Firmware ID Public Key (%s)\n",
            mrgmsg, sizeof mrgmsg);

        sbc_err_sysprn(SBC_LOG_CMN_PRIO_ERR, 2,
                 SYS_LOG_HOST_BOOT,
                 SYS_LOG_APP_NAME,
                 SYS_LOG_CSC_NAME,
                 1,
                 SYS_LOG_EVT_DETECTION,
                 mrgmsg);
        ret = SBCINVPARAM;
        goto errdone;
    }
#endif
//  sbc_err_sysprn(SBC_LOG_CMN_PRIO_ERR, 2,
//         L"SBC",
//         L"FSBL",
//         L"Weapon System",
//         1,
//         L"EVT",
//         L"Device ID Verify Done");
    

errdone:
    if (ret != SBCOK) {
//    sbc_err_sysprn(SBC_LOG_CMN_PRIO_ERR, 2,
//           L"SBC",
//           L"FSBL",
//           L"Weapon System",
//           1,
//           L"EVT",
//           L"Device ID Verify Fail");
    }
    return ret;

}

SBCStatus  SBC_OSIdKyeVerify(VOID *priv)
{
    boot_proc_t *bp = NULL;
    SBCStatus ret = SBCOK;
    at_key_t key_pair;
    at_key_t rcv_key_pair;

    VOID *ctx = NULL;
    BOOLEAN retval;

    UINT8 pubkey[64] = {0,};
    UINTN pubkeyl = 0;
    UINT8 *loadbuf;
    UINT32 ldlen = BASE_ANS_BLK_LEN;
    UINTN systm_lba = 0;
    SBC_AESGcmCtx  decctx;
    SBC_AESContext  aesctx;

    UINTN offset = 0;
    UINTN calen = 0;

    UINT8 decbuf[2048] = {0,};
    UINT8 secret_key[SYS_OSID_KEY_LEN] = {0, };

    VOID *blkio = NULL;
    VOID *osid = NULL;

    dprint("Starting !!!");

    bp = (boot_proc_t *)priv;

    blkio = bp->blkhnd;
    osid = ((atp_ident_t *)bp->keyinfo)->osid;

    // Generate the Public Key
    ret = SBC_DICESeedKeyPair(osid, &key_pair);
    SBC_RET_VALIDATE_ERRCODEMSG((ret == SBCOK), SBCINVPARAM, "OS ID Key-pair gen fail");

    SBC_external_mem_print_bin("Org. Priv", key_pair.d, sizeof key_pair.d);
    SBC_external_mem_print_bin("Org. Pub", key_pair.q.value , sizeof key_pair.q);

    // Device ID certificate Load 
    systm_lba = (SYS_CONF_START_OFS >> SBC_RAWPRT_DFLT_SHIFT);
    dprint("Sys Conf offset (402653696) %d", SYS_CONF_START_OFS);
    dprint("System Setting Start LBA (768433) : %lu (0x%lx)", systm_lba, systm_lba);
    ldlen = ALIGN_VALUE(SYS_SETTING_STORAGE_LEN, ((EFI_BLOCK_IO_PROTOCOL *)blkio)->Media->BlockSize);
    loadbuf = AllocateZeroPool(ldlen);
    SBC_RET_VALIDATE_ERRCODEMSG((loadbuf != NULL), SBCNULLP, "Buffer invalid object");

    ret = SBC_RawPrtReadBlock(blkio, 
                              (VOID *)loadbuf, 
                              &ldlen, 
                              systm_lba);
    if (ret != SBCOK) {
       dprint("SBC_RawPrtReadBlock fail (%p)\n", blkio);
        goto errdone;
    }

    //SBC_mem_print_bin("12 Device ID cert", (UINT8 *)loadbuf, ldlen);
#if 1 //ndef _SSBL_TEST_ 
    offset = SYS_CONF_OSID_CRT_OFS;
#else

    UINT8 rawData[428] = {                                           
    	0x8C, 0x01, 0x00, 0x00, 0xD9, 0xFA, 0xCB, 0x23, 0x89, 0xBA, 0xE4, 0x9A,
    	0xCB, 0x75, 0xB2, 0x8B, 0x3D, 0xC2, 0x5C, 0x9E, 0xA7, 0xF2, 0x94, 0x66,
    	0x70, 0x22, 0x4A, 0xDF, 0x2D, 0x70, 0x36, 0xAB, 0xA7, 0x6C, 0xE0, 0xC3,
    	0x3D, 0xDD, 0xB4, 0xBD, 0x85, 0xD0, 0x86, 0xC4, 0x53, 0x2F, 0xBE, 0x7E,
    	0x73, 0x83, 0x23, 0x0B, 0x15, 0xA5, 0x65, 0xE3, 0xB0, 0x84, 0x0A, 0x4A,
    	0x3F, 0xC6, 0xED, 0xD7, 0xED, 0x5A, 0x5A, 0x53, 0x80, 0xA8, 0xAB, 0x02,
    	0xA2, 0xE8, 0x48, 0x4D, 0x4C, 0x2E, 0x27, 0x5D, 0xF8, 0xF3, 0xAC, 0x06,
    	0x21, 0xFE, 0xA4, 0x7F, 0xE6, 0x2A, 0x4D, 0xC9, 0x7B, 0x73, 0x33, 0xEF,
    	0xB3, 0xD8, 0x6E, 0xA7, 0xB4, 0x4C, 0xD4, 0xB5, 0x5E, 0x06, 0xA4, 0x87,
    	0xCF, 0x44, 0xA0, 0xE1, 0x6F, 0x00, 0x62, 0xA5, 0xC1, 0x51, 0x27, 0x89,
    	0xD0, 0xFF, 0x40, 0x56, 0xAF, 0x29, 0x57, 0x45, 0x22, 0x3B, 0x2A, 0xE1,
    	0xBF, 0x32, 0x59, 0x05, 0xC3, 0x05, 0x19, 0x62, 0x9D, 0x79, 0x56, 0x70,
    	0xDC, 0x30, 0xE0, 0xFE, 0x5F, 0x1D, 0x2F, 0xB8, 0x16, 0x71, 0x3B, 0x2B,
    	0x03, 0x8A, 0x0B, 0x29, 0x67, 0x97, 0x42, 0x08, 0x0D, 0x9D, 0xD0, 0x20,
    	0xE1, 0x80, 0x0A, 0x29, 0xE3, 0xC7, 0x46, 0x2C, 0xFE, 0xC3, 0xC0, 0x81,
    	0xC9, 0x33, 0x3F, 0x81, 0xAC, 0x7D, 0x9A, 0xC2, 0xBE, 0x8A, 0x4E, 0xD1,
    	0x76, 0xFB, 0x25, 0xB3, 0x07, 0x17, 0x08, 0x5B, 0x5C, 0x67, 0x06, 0xDB,
    	0x02, 0xF5, 0xFC, 0x09, 0x10, 0xD4, 0x06, 0xB9, 0xAD, 0xAE, 0x4F, 0xF7,
    	0x16, 0x80, 0x7F, 0x21, 0x0A, 0x56, 0x48, 0xA1, 0x32, 0x69, 0xA9, 0xDB,
    	0x52, 0x5B, 0x43, 0x87, 0xBD, 0x08, 0x8E, 0x06, 0x91, 0x88, 0x9E, 0x66,
    	0x82, 0x47, 0x6B, 0x69, 0xE7, 0x12, 0x9A, 0xDE, 0xB9, 0x61, 0x2F, 0xE3,
    	0xDC, 0x71, 0x8E, 0x61, 0xE9, 0x5A, 0x8E, 0x17, 0x90, 0xBF, 0x35, 0x9B,
    	0x4D, 0x16, 0xAF, 0x72, 0x16, 0x54, 0x0D, 0xA6, 0xCD, 0x0A, 0xFF, 0x76,
    	0xB8, 0x49, 0x0C, 0xF2, 0x8E, 0x29, 0x04, 0x77, 0x43, 0x5C, 0x69, 0x83,
    	0x34, 0xA8, 0xA4, 0x6B, 0xD6, 0x52, 0x8A, 0x93, 0x2D, 0x23, 0x46, 0x8F,
    	0xBD, 0x08, 0x84, 0x2C, 0x3F, 0xA5, 0x52, 0x5B, 0x90, 0x75, 0x10, 0xF7,
    	0xF6, 0x93, 0x97, 0x89, 0xA9, 0xC1, 0x41, 0x6A, 0xD9, 0xA2, 0xC0, 0x9A,
    	0x3D, 0xDB, 0x41, 0x00, 0xA3, 0x8D, 0x89, 0xCD, 0x41, 0x71, 0x7B, 0x31,
    	0xE6, 0x90, 0x5A, 0x9D, 0x33, 0x79, 0x02, 0xC6, 0xDD, 0xB0, 0x49, 0x96,
    	0x92, 0xD5, 0xE6, 0xD9, 0xE5, 0x4C, 0x8D, 0xC8, 0x0C, 0x8C, 0x7F, 0x0D,
    	0xEA, 0x7B, 0xD4, 0xA2, 0x52, 0xC2, 0x95, 0x81, 0x5B, 0x11, 0xFB, 0x6D,
    	0x75, 0x9F, 0xD8, 0xEE, 0x0E, 0x19, 0x5A, 0xFE, 0xA0, 0xC2, 0x3D, 0x01,
    	0x80, 0x38, 0xBF, 0xC2, 0xBC, 0x8A, 0xAA, 0x30, 0x47, 0xC6, 0x34, 0x8B,
    	0x16, 0x62, 0x7D, 0x39, 0x46, 0x66, 0x58, 0x8C, 0x75, 0x4B, 0x37, 0x87,
    	0xCE, 0x53, 0x4A, 0x35, 0xEE, 0x9B, 0x9E, 0x30, 0xF2, 0xD3, 0xB4, 0xA5,
    	0x85, 0x85, 0xF8, 0x2B, 0x90, 0xB4, 0xFE, 0xF7                         
    };                                                                       

    loadbuf = rawData;
    offset = 0;
#endif

    CopyMem((void *)&calen, (void *)&loadbuf[offset], 4);

    dprint("OS ID CA Len : %d ", calen);
    offset += 4;
    // Decrypt 

    SBC_mem_print_bin("OS ID cert", (UINT8 *)&loadbuf[offset], calen);

    decctx.msg.value = &loadbuf[offset];
    decctx.msg.length = calen;

    offset += calen;
    decctx.iv.value = &loadbuf[offset];
    decctx.iv.length = BASE_ANS_IV_KEY_STR;
    SBC_mem_print_bin("OS ID IV", (UINT8 *)&loadbuf[offset], BASE_ANS_IV_KEY_STR);

    
    offset += BASE_ANS_IV_KEY_STR;
    decctx.tag.value = &loadbuf[offset];
    decctx.tag.length = BASE_ANS_TAG_LEN;
    SBC_mem_print_bin("OS ID TAG", (UINT8 *)&loadbuf[offset], BASE_ANS_TAG_LEN);

#ifdef _SSBL_TEST_
    UINTN idx = 0;

    for (idx = 0; idx < 32; idx++)
        secret_key[idx] = idx + 20;
#else
    // Device Secret Key Create 
    ret = SBC_DeviceSecuirtyKeyCreate(secret_key);
    SBC_RET_VALIDATE_ERRCODEMSG((ret == SBCOK), 
                                SBCINVPARAM, 
                                "OS ID Key-pair gen fail");

#endif
    SBC_mem_print_bin("Device Secert Key", secret_key, BASE_ANS_KEY_STR);
    decctx.key.value = secret_key;
    decctx.key.length = BASE_ANS_KEY_STR;
    //SBC_mem_print_bin("Dec Key", (UINT8 *)deckey, BASE_ANS_KEY_STR);

    decctx.aad.value = NULL;
    decctx.aad.length = 0;

    decctx.out.value = decbuf;
    decctx.out.length = calen;

    aesctx.gcm = &decctx;
    aesctx.algoid = SBC_CIPHER_AES_GCM;

    if (SBC_AESGcmDecrypt(&aesctx) != SBCOK) {
        eprint("OS CA decrypt fail");
        ret = SBCDECFAIL;
        goto errdone;
    }

    SBC_mem_print_bin("Decrypt OS ID cert", (UINT8 *)decbuf, calen);

    if (((rawprt_hdr_t *)bp->rawprt_hdr)->rcvmode /*&& (bp->bm == BOOT_MODE_NORMAL)*/) {
        // Key Pair compare 
//      dprint("Boot Mode is NORMAL and it's run from Recovery Mode");
//
//      //TODO
//      //A. Private and Public Key extract from Buffer.
//      ret = SBC_DICESeedKeyPair(osid, &rcv_key_pair);
//      //B. Public Key compute using Private Key.
//      CopyMem(pubkey, rcv_key_pair.q.value, sizeof rcv_key_pair.q.value);
//      pubkeyl = sizeof rcv_key_pair.q.value;

        // Key Pair compare 
        dprint("Boot Mode is NORMAL and it's run from Recovery Mode");

        //TODO 
        //A. Private and Public Key extract from Buffer.
        //ret = SBC_DICESeedKeyPair(fwid, &rcv_key_pair);
        //B. Public Key compute using Private Key.

        CopyMem(&rcv_key_pair, decbuf, calen);
        CopyMem(pubkey, rcv_key_pair.q.value, sizeof rcv_key_pair.q.value); 
        pubkeyl = sizeof rcv_key_pair.q.value;
    }
    else {

        // Get Public Key
        ret = SBC_EcGetPublicKeyFromPem((CONST UINT8 *)decbuf, calen, &ctx);
        SBC_RET_VALIDATE_ERRCODEMSG((ret == SBCOK), SBCINVPARAM, "Public key extract fail");

        pubkeyl = ATP_IDENT_KEY_STG * 2;
        retval = EcGetPubKey(ctx, pubkey, &pubkeyl);
        if(retval != TRUE) {
            ret = SBCFAIL;
            eprint("EcGetPubKey fail %d", retval);
            goto errdone;
        }
    }

#ifdef _SSBL_TEST_
    SBC_external_mem_print_bin("Certificate Pubkey", pubkey, pubkeyl);
    dprint("PublicK Key Match Done ...");

#else
    SBC_external_mem_print_bin("OS ID Pubkey", key_pair.q.value, key_pair.ql);
    if(CompareMem(key_pair.q.value,  pubkey, pubkeyl) != 0) {
        
        SBC_BuildHexFormattedMessage(
            (CONST VOID *)pubkey, (UINTN)pubkeyl,
            L"SBC_Dice_Verify Failed to OSID Public Key (%s)\n",
            mrgmsg, sizeof mrgmsg);

        sbc_err_sysprn(SBC_LOG_CMN_PRIO_ERR, 2,
                 SYS_LOG_HOST_BOOT,
                 SYS_LOG_APP_NAME,
                 SYS_LOG_CSC_NAME,
                 1,
                 SYS_LOG_EVT_DETECTION,
                 mrgmsg);
        ret = SBCINVPARAM;
        goto errdone;
    }
#endif
//  sbc_err_sysprn(SBC_LOG_CMN_PRIO_ERR, 2,
//         L"SBC",
//         L"FSBL",
//         L"Weapon System",
//         1,
//         L"EVT",
//         L"Device ID Verify Done");
    

errdone:
    if (ret != SBCOK) {
//    sbc_err_sysprn(SBC_LOG_CMN_PRIO_ERR, 2,
//           L"SBC",
//           L"FSBL",
//           L"Weapon System",
//           1,
//           L"EVT",
//           L"Device ID Verify Fail");
    }
    return ret;



}

SBCStatus SBC_DiceIDKeyVerify(VOID *priv)
{
    SBCStatus ret = SBCOK;
   
    SBC_RET_VALIDATE_ERRCODEMSG((priv != NULL), SBCNULLP, "Invalid Pointer");

    ret = SBC_FirmwareIdKyeVerify(priv);
    if (ret != SBCOK) {
        goto errdone;
    }

    sbc_err_sysprn(SBC_LOG_CMN_PRIO_INFO, 2,
           SYS_LOG_HOST_BOOT,
           SYS_LOG_APP_NAME,
           SYS_LOG_CSC_NAME,
           1,
           SYS_LOG_EVT_VALDIATION,
           L"SBC_Dice_Key FWID Verify Success");

    ret = SBC_OSIdKyeVerify(priv);
    if (ret != SBCOK) {
        goto errdone;
    }

    sbc_err_sysprn(SBC_LOG_CMN_PRIO_INFO, 2,
               SYS_LOG_HOST_BOOT,
               SYS_LOG_APP_NAME,
               SYS_LOG_CSC_NAME,
               1,
               SYS_LOG_EVT_VALDIATION,
               L"SBC_Dice_Key OSID Verify Success");
 

errdone:
#ifdef _FORCED_SHUTDOWN_
    if (ret != SBCOK) {
        SBC_ShutdownSystem();
    }
#endif
    return ret;



}


SBCStatus  SBC_DeviceIdKyeVerify(VOID *blkio, UINT8 *devid, UINT8 *deckey)
{
    SBCStatus ret = SBCOK;
    at_key_t key_pair;

    VOID *ctx = NULL;
    BOOLEAN retval;

    UINT8 pubkey[64] = {0,};
    UINTN pubkeyl = 0;
    UINT8 *loadbuf;
    UINT32 ldlen = BASE_ANS_BLK_LEN;
    UINTN baseansr_lba = 0;
    SBC_AESGcmCtx  decctx;
    SBC_AESContext  aesctx;

    UINTN offset = 0;
    UINTN calen = 0;

    UINT8 decbuf[2048] = {0,};
    UINT8 secret_key[SYS_OSID_KEY_LEN] = {0, };


    // Generate the Public Key
    ret = SBC_DICESeedKeyPair(devid, &key_pair);
    SBC_RET_VALIDATE_ERRCODEMSG((ret == SBCOK), SBCINVPARAM, "Device ID Key-pair gen fail");


    // Device ID certificate Load 
    baseansr_lba = (SYS_CONF_START_OFS >> SBC_RAWPRT_DFLT_SHIFT);
    ldlen = ALIGN_VALUE(SYS_SETTING_STORAGE_LEN, ((EFI_BLOCK_IO_PROTOCOL *)blkio)->Media->BlockSize);
    loadbuf = AllocateZeroPool(ldlen);
    SBC_RET_VALIDATE_ERRCODEMSG((loadbuf != NULL), SBCNULLP, "Buffer invalid object");

    ret = SBC_RawPrtReadBlock(blkio, 
                              (VOID *)loadbuf, 
                              &ldlen, 
                              baseansr_lba);
    if (ret != SBCOK) {
       dprint("SBC_RawPrtReadBlock fail (%p)\n", blkio);
        goto errdone;
    }

    offset = SYS_CONF_DEVID_CRT_OFS;
    CopyMem((void *)&calen, (void *)&loadbuf[offset], 4);
    offset += 4;
    // Decrypt 

    decctx.msg.value = &loadbuf[offset];
    decctx.msg.length = calen;

    offset += calen;
    decctx.iv.value = &loadbuf[offset];
    decctx.iv.length = BASE_ANS_IV_KEY_STR; 
    
    offset += BASE_ANS_IV_KEY_STR;
    decctx.tag.value = &loadbuf[offset];
    decctx.tag.length = BASE_ANS_TAG_LEN;


    ret = SBC_DeviceSecuirtyKeyCreate(secret_key);
    SBC_RET_VALIDATE_ERRCODEMSG((ret == SBCOK), 
                                SBCINVPARAM, 
                                "Device ID Key-pair gen fail");
    decctx.key.value = deckey;
    decctx.key.length = BASE_ANS_KEY_STR;

    decctx.aad.value = NULL;
    decctx.aad.length = 0;

    decctx.out.value = decbuf;
    decctx.out.length = calen;

    aesctx.gcm = &decctx;
    aesctx.algoid = SBC_CIPHER_AES_GCM;

    if (SBC_AESGcmDecrypt(&aesctx) != SBCOK) {
        eprint("DeviceID CA decrypt fail");
        ret = SBCDECFAIL;
        goto errdone;
    }


    // Get Public Key
    ret = SBC_EcGetPublicKeyFromPem((CONST UINT8 *)decbuf, calen, &ctx);
    SBC_RET_VALIDATE_ERRCODEMSG((ret == SBCOK), SBCINVPARAM, "Public key extract fail");

    retval = EcGetPubKey(ctx, pubkey, &pubkeyl);
    if(retval != TRUE) {
        ret = SBCFAIL;
        eprint("EcGetPubKey fail %r", retval);
        goto errdone;
    }

    SBC_external_mem_print_bin("Device ID Pubkey", key_pair.q.value, key_pair.ql);
    SBC_external_mem_print_bin("Certificate Pubkey", pubkey, pubkeyl);


    if(CompareMem(key_pair.q.value,  pubkey, pubkeyl) != 0) {
        eprint("CA public key verify fail");
        ret = SBCINVPARAM;
        goto errdone;
    }

//  sbc_err_sysprn(SBC_LOG_CMN_PRIO_ERR, 2,
//         L"SBC",
//         L"FSBL",
//         L"Weapon System",
//         1,
//         L"EVT",
//         L"Device ID Verify Done");
    

errdone:
    if (ret != SBCOK) {
//    sbc_err_sysprn(SBC_LOG_CMN_PRIO_ERR, 2,
//           L"SBC",
//           L"FSBL",
//           L"Weapon System",
//           1,
//           L"EVT",
//           L"Device ID Verify Fail");
    }
    return ret;

}

SBCStatus SBC_BaseAnswerEncryptStore(VOID *blkhnd, UINT8* msg, UINT32 msgl, UINT8 *key, UINT32 keyl)
{
    SBCStatus ret = SBCOK;
    base_ansid_t ansid;

    SBC_AESContext aesctx;
    SBC_AESGcmCtx  ctx;


    ZeroMem((void *)&ansid ,sizeof ansid);
    CopyMem((void *)ansid.key, key, BASE_ANS_KEY_STR);

    RandomBytes((void *)ansid.iv, BASE_ANS_IV_KEY_STR); // Initial Vector 

    dprint("B-Ansr Message Len : %d", msgl);
    SBC_external_mem_print_bin("Plain B-Ansr Message", msg, msgl);


    // A. Encrypt the Message 

    ctx.key.value = ansid.key;
    ctx.key.length = BASE_ANS_KEY_STR;
    ctx.iv.value = ansid.iv;
    ctx.iv.length = BASE_ANS_IV_KEY_STR;
    ctx.aad.value = NULL;
    ctx.aad.length = 0;
    ctx.msg.value = msg;
    ctx.msg.length = msgl;
    ctx.tag.value = ansid.tag;
    ctx.tag.length = BASE_ANS_TAG_LEN;

    ctx.out.value = ansid.encmsg;
    ctx.out.length = sizeof ansid.encmsg;

    

    aesctx.gcm = &ctx;
    aesctx.algoid = SBC_CIPHER_AES_GCM;

    ret = SBC_AESEncrypt(&aesctx);
    if (ret != SBCOK) {
        SBC_BuildHexFormattedMessage(
            (CONST VOID *)ctx.key.value,
            32,
            L"SFR-Vendor-SP Base Answer Encrypt Fail (%s) \n",
            mrgmsg, sizeof mrgmsg);

        sbc_err_sysprn(SBC_LOG_CMN_PRIO_ERR, 2,
                     SYS_LOG_HOST_BOOT,
                     SYS_LOG_APP_NAME,
                     SYS_LOG_CSC_NAME,
                     0,
                     SYS_LOG_EVT_DETECTION,
                     mrgmsg);
      goto errdone;
    }

    ansid.msglen = ctx.out.length;
    
    //dprint("B-Ansr Message Len : %d", ansid.msglen);
    SBC_external_mem_print_bin("B-Ansr Message", ansid.encmsg, ansid.msglen);
    SBC_external_mem_print_bin("B-Ansr IV", ansid.iv, BASE_ANS_IV_KEY_STR);
    SBC_external_mem_print_bin("B-Ansr Tag", ansid.tag, BASE_ANS_TAG_LEN);
    SBC_external_mem_print_bin("B-Ansr Key", ansid.key, BASE_ANS_KEY_STR);



    ret = SBC_BaseAnswerStore(blkhnd, (VOID *)&ansid);
    if (ret != SBCOK) {
        SBC_BuildHexFormattedMessage(
            (CONST VOID *)ansid.encmsg,
            ansid.msglen,
            L"SFR-Vendor-SP Base Answer Storet Fail (%s) \n",
            mrgmsg, sizeof mrgmsg);

        sbc_err_sysprn(SBC_LOG_CMN_PRIO_ERR, 2,
                     SYS_LOG_HOST_BOOT,
                     SYS_LOG_APP_NAME,
                     SYS_LOG_CSC_NAME,
                     0,
                     SYS_LOG_EVT_DETECTION,
                     mrgmsg);
      goto errdone;
    }

    SBC_BuildHexFormattedMessage(
            (CONST VOID *)ansid.encmsg,
            ansid.msglen,
            L"SFR-Vendor-SP Base Answer Store Success (%s) \n",
            mrgmsg, sizeof mrgmsg);

    sbc_err_sysprn(SBC_LOG_CMN_PRIO_ERR, 2,
                     SYS_LOG_HOST_BOOT,
                     SYS_LOG_APP_NAME,
                     SYS_LOG_CSC_NAME,
                     0,
                     L"Validation",
                     mrgmsg);
    ret = SBCOK;
errdone:

//  if (msg != NULL) {
//    FreePool(msg);
//  }

    return ret;

}

SBCStatus  SBC_BaseAnswerValidate(VOID *blkhnd, UINT8 *answer, UINTN answerl, UINT8 *key, UINTN keylen, BOOLEAN ischeck)
{
    SBCStatus ret = SBCOK;
    //UINT8 rdbuf[256];
    //UINT8 baseanswer[256] = {0, };
    base_ansid_t ansid;
    SBC_AESContext aesctx;
    SBC_AESGcmCtx  ctx;

    UINT8 decbuf[BASE_ANS_STREAM_LEN] = {0,};

    dprint("Base Answer verifing starting !!!");

    SBC_RET_VALIDATE_ERRCODEMSG((answer != NULL), SBCNULLP, "Answer is Nill");
#ifdef _TEST_ERROR_SET_    
    if (NvramErr_IsTrue(ERR_BASEANSWR_DEC)) {
        sbc_err_sysprn(SBC_LOG_CMN_PRIO_INFO, 2,
                 SYS_LOG_HOST_BOOT,
                 SYS_LOG_APP_NAME,
                 SYS_LOG_CSC_NAME,
                 0,
                 SYS_LOG_EVT_DETECTION,
                 L"SBC_VENDOR_SP Fail to Base Answer Decrypt");
        ret = SBCFAIL;
        goto errdone;
    }

    if (NvramErr_IsTrue(ERR_BASEANSWR_ENC)) {
        sbc_err_sysprn(SBC_LOG_CMN_PRIO_INFO, 2,
                 SYS_LOG_HOST_BOOT,
                 SYS_LOG_APP_NAME,
                 SYS_LOG_CSC_NAME,
                 0,
                 SYS_LOG_EVT_DETECTION,
                 L"SBC_VENDOR_SP Fail to Base Answer Encrypt");
        ret = SBCFAIL;
        goto errdone;
    }

#endif

    // Read the Base Answer from Disk 

    ZeroMem((void *)&ctx, sizeof ctx);
    ZeroMem((void *)&aesctx, sizeof aesctx);
    ZeroMem(&ansid, sizeof ansid);

    ret = SBC_BaseAnswerExtractFromDisk(blkhnd, &ansid);
    SBC_RET_VALIDATE_ERRCODEMSG((ret == SBCOK),ret, "Disk read fail");
   
    //SBC_mem_print_bin("Base Answer Encrypt", (UINT8 *)&ansid ,64);



    ctx.key.value = key;
    ctx.key.length = BASE_ANS_KEY_STR;
    ctx.iv.value = ansid.iv;
    ctx.iv.length = BASE_ANS_IV_KEY_STR; 
    ctx.aad.value = NULL;
    ctx.aad.length = 0;
    ctx.msg.value = ansid.encmsg;
    ctx.msg.length = ansid.msglen;
    ctx.tag.value = ansid.tag;
    ctx.tag.length = BASE_ANS_TAG_LEN;

    ctx.out.value = decbuf;
    ctx.out.length = ansid.msglen;

    aesctx.gcm = &ctx;
    aesctx.algoid = SBC_CIPHER_AES_GCM;

    dprint("*** Base Answer Information --->");
    SBC_external_mem_print_bin("Key", (UINT8 *)ctx.key.value, ctx.key.length);
    SBC_external_mem_print_bin("IV", (UINT8 *)ctx.iv.value , BASE_ANS_IV_KEY_STR);
    SBC_external_mem_print_bin("TAG", (UINT8 *)ctx.tag.value , BASE_ANS_TAG_LEN);
    SBC_external_mem_print_bin("Enc Message", (UINT8 *)ctx.msg.value, ctx.msg.length);


    if (SBC_AESGcmDecrypt(&aesctx) != SBCOK) {
        SBC_BuildHexFormattedMessage(
            (CONST VOID *)ctx.key.value,
            32,
            L"SFR-Vendor-SP BaseAnswer decrypt fail (Key - %s) \n",
            mrgmsg, sizeof mrgmsg);

        sbc_err_sysprn(SBC_LOG_CMN_PRIO_ERR, 2,
                     SYS_LOG_HOST_BOOT,
                     SYS_LOG_APP_NAME,
                     SYS_LOG_CSC_NAME,
                     0,
                     SYS_LOG_EVT_DETECTION,
                     mrgmsg);
        ret = SBCFAIL;
        goto errdone;
    }


#ifndef _ATSW_INTGR_TEST_
    SBC_external_mem_print_bin("Raw Partitoin Base Answer msg", answer, answerl);
    SBC_external_mem_print_bin("Base Answer decrypt msg", decbuf, ctx.out.length);
    if ((CompareMem((const void *)decbuf, (const void *)answer, answerl) != 0) && (ischeck == TRUE)) {
#else
    UINT8 test_answering[16] = {
      'A','n','t','i','-','T','a','m','p','e','r','i','n','g'
    };
    SBC_external_mem_print_bin("plain msg", test_answering, sizeof test_answering);
    SBC_external_mem_print_bin("decrypt msg", decbuf, ctx.out.length);
    if ((CompareMem((const void *)decbuf, (const void *)test_answering, 16) != 0) && (ischeck == TRUE)) {
#endif
      //Print(L"Base Answer validate Fail \n");


//      ZeroMem(mrgmsg, sizeof mrgmsg);
//      UnicodeSPrint(mrgmsg, sizeof mrgmsg, L"Base Answer validate fail(%s:%s) \n",answer,decbuf);
#ifndef _ATSW_INTGR_TEST_
            SBC_BuildHexFormattedMessage(
                (CONST VOID *)ctx.key.value,
                ctx.out.length,
                L"SFR-Vendor-SP Mismatched Base Answer (%s) \n",
                mrgmsg, sizeof mrgmsg);

            sbc_err_sysprn(SBC_LOG_CMN_PRIO_ERR, 2,
                         SYS_LOG_HOST_BOOT,
                         SYS_LOG_APP_NAME,
                         SYS_LOG_CSC_NAME,
                         0,
                         SYS_LOG_EVT_DETECTION,
                         mrgmsg);

            ret = SBCFAIL;

            goto errdone;
#endif

    }
    else if(ischeck == FALSE) {
      CopyMem((void *)answer, (void *)decbuf, ctx.out.length);
      return SBCOK;

    }

//  ZeroMem(mrgmsg, sizeof mrgmsg);
//  UnicodeSPrint(mrgmsg, sizeof mrgmsg, L"Base Answer validate Success (%s:%s) \n",answer,decbuf);

    //
    // T-SAT-PWT-SFR-003
    // Validation 
    //
    sbc_err_sysprn(SBC_LOG_CMN_PRIO_INFO, 2,
         SYS_LOG_HOST_BOOT,
         SYS_LOG_APP_NAME,
         SYS_LOG_CSC_NAME,
         3,
         SYS_LOG_EVT_VALDIATION,
         L"SBC_Integrity_OSID derived answer matched known answer");

    return ret;
errdone:

    //
    // T-SAT-PWT-SFR-003
    // Detection 
    //
    sbc_err_sysprn(SBC_LOG_CMN_PRIO_ERR, 2,
       SYS_LOG_HOST_BOOT,
       SYS_LOG_APP_NAME,
       SYS_LOG_CSC_NAME,
       3,
       SYS_LOG_EVT_DETECTION,
       L"SBC_tamper_OSID derived answer mismatched known answer");

    return ret;

}
#if 0
SBCStatus  SBC_SSBL_Verify(VOID *blkhnd, VOID *ansr,  UINTN nrombank)
{
    SBCStatus       ret = SBCOK;

    UINTN           startlba = 0;
  

    UINT32          imglen = SBC_RAWPRT_DFLT_BLK_SZ;
    UINT8           imghdr[SBC_RAWPRT_DFLT_BLK_SZ] = {0, };
    UINT8           *loadimg = NULL;
    [[gnu::unused]]UINT8           *temp = NULL;
    UINTN           bsofs = 0; // Boot Sector Offset
    UINT32          last_of_fsbl = 0;
    UINT8           *infostart = NULL;
    UINT32          bsinfolen = 0;
    fsbl_bsinfo_t   bsinfo;

    [[maybe_unused]]UINT32          bsptrcnt = 0;
    [[maybe_unused]]UINT8           HashValue[256];
    [[maybe_unused]]UINT32          HashSize =0;
    [[maybe_unused]]UINT32          fsbl_len =0;
    [[maybe_unused]]VOID            *EcPubKey = NULL;
    [[maybe_unused]]UINTN           HandleCount;
    [[maybe_unused]]fsbl_bsinfo_ptr_t info = {NULL, NULL, NULL, NULL};
    [[maybe_unused]]BOOLEAN         retbool = TRUE;


    LV_t            rdlv = {
            .length = 0,
            .value = NULL
    };
    bsofs = (BOOT_SECTOR1_OFS | ((nrombank - 1) << 20));
    startlba = ((bsofs | BOOT_SSBL_OFS) >> SBC_RAWPRT_DFLT_SHIFT);

    ret = SBC_RawPrtReadBlock(blkhnd, (void *)imghdr, &imglen, startlba);
    if (ret != SBCOK) {
        eprint("SSBL Factory Block Read Fail \n");
        goto errdone;
    }

    CopyMem((void *)&imglen, &imghdr[0], sizeof imglen);
    imglen = ALIGN_VALUE(imglen, SBC_RAWPRT_DFLT_BLK_SZ);

    loadimg = AllocateReservedZeroPool(imglen);
    SBC_RET_VALIDATE_ERRCODEMSG((loadimg != NULL), SBCNULLP, "Allocate Memory Fail");

    ret = SBC_RawPrtReadBlock(blkhnd, (void *)loadimg, &imglen, startlba);
    SBC_RET_VALIDATE_ERRCODEMSG((ret == SBCOK), ret, "SSBL Factory Block Read Fail ");

    rdlv.value = (UINT8 *)&loadimg[4];
    rdlv.length = imglen;
    last_of_fsbl =  rdlv.length - FSBL_BNIFO_SIZE;
    infostart = &((UINT8 *)rdlv.value)[last_of_fsbl];

    ZeroMem((void *)&bsinfo, sizeof bsinfo);
    CopyMem((void *)&bsinfo, (void *)infostart, sizeof bsinfo);

    dprint("----------- SSBL Boot Service Informmtion ------------");
    dprint("Signature Len     : %d", bsinfo.m.siglen );
    dprint("Firmware Info Len : %d", bsinfo.m.fwinfolen );
    dprint("Certificate Len   : %d", bsinfo.m.certlen );
    dprint("BaseAnswer Len    : %d", bsinfo.m.banswlen );
    dprint("BSinfo verdion    : %d", bsinfo.m.bsinfv );
    dprint("Spec.1 Value      : %d", bsinfo.m.reserv1 );
    dprint("Spec.2 Value      : %d", bsinfo.m.reserv2 );

    bsinfolen = bsinfo.m.siglen + bsinfo.m.fwinfolen + bsinfo.m.certlen  + bsinfo.m.banswlen;

    fsbl_len = last_of_fsbl = rdlv.length - FSBL_BNIFO_SIZE - bsinfolen;
    infostart = &((UINT8 *)rdlv.value)[last_of_fsbl];

    info.baseansw = (VOID *)&infostart[bsptrcnt];
    bsptrcnt += bsinfo.m.banswlen;

    //SBC_external_mem_print_bin("Base Answer", (UINT8 *)info.baseansw,  bsinfo.m.banswlen );

    info.fwinfo = (VOID *)&infostart[bsptrcnt];
    bsptrcnt += bsinfo.m.fwinfolen;

    //SBC_external_mem_print_bin("FW Info", (UINT8 *)info.fwinfo,  bsinfo.m.fwinfolen );

    info.certi = (VOID *)&infostart[bsptrcnt];
    bsptrcnt += bsinfo.m.certlen;

    //SBC_external_mem_print_bin("Certificate", (UINT8 *)info.certi,  bsinfo.m.certlen );

    info.signature = (VOID *)&infostart[bsptrcnt];
    bsptrcnt += bsinfo.m.siglen;    
    
//  retbool = EcGetPublicKeyFromX509((CONST UINT8  *)info.certi, (UINTN)bsinfo.m.certlen,  &EcPubKey);
//  if (retbool != TRUE) {
//      eprint("EcGetPublicKeyFromX509 fail");
//      ret = SBCFAIL;
//      goto errdone;
//  }

//  dprint("SSBL image len : %d", fsbl_len);
//
//  ret = SBC_HashCompute(
//                   NULL, /* Not yet used */
//                   rdlv.value,
//                   fsbl_len,
//                   HashValue
//                ) ;
//
//
//  HashSize = 32;
//
//  retbool = EcDsaVerify(
//      EcPubKey,
//      CRYPTO_NID_SHA256,
//      HashValue,
//      HashSize,
//      info.signature,
//      bsinfo.m.siglen
//      );
//
//  if (retbool != TRUE) {
//      eprint("FSBL Verify fail");
//      ret = SBCFAIL;
//      goto errdone;
//  }
//
//  if (ansr == NULL) {
//    goto errdone;
//  }
//
//  //sbc_err_sysprn(SBC_LOG_CMN_PRIO_INFO, 2, L"SBC", L"FSBL", L"CSC-01", 23, L"VERIFY", L"SSBL Integrate check is Done\n");
// dprint("SSBL Verify Success !!!\n");
//
//  ((LV_t *)ansr)->value = AllocateZeroPool(bsinfo.m.banswlen);
//  if (((LV_t *)ansr)->value == NULL) {
//      //sbc_err_sysprn(SBC_LOG_CMN_PRIO_INFO, 2, L"SBC", L"FSBL", L"CSC-01", 23, L"VERIFY", L"FSBL Integrate check is Done\n");
//      eprint("Base Answer buffer allocate fail");
//      ret = SBCNULLP;
//      goto errdone;
//  }
//
//  ((LV_t *)ansr)->length = bsinfo.m.banswlen;
//  CopyMem(((LV_t *)ansr)->value, info.baseansw, bsinfo.m.banswlen);


errdone:

//  if (EcPubKey != NULL) {
//    EcFree(EcPubKey);
//  }
//  if (rdlv.value != NULL) {
//    FreePool(rdlv.value);
//    rdlv.value = NULL;
//  }

//  if (ret != SBCOK) {
//      sbc_err_sysprn(SBC_LOG_CMN_PRIO_INFO, 2, L"SBC", L"FSBL", L"CSC-01", 23, L"VERIFY", L"SSBL Integrate check is Fail\n");
//  }

    return ret;

}
#endif

SBCStatus  SBC_SSBL_Verify(VOID *blkhnd, VOID *ansr, UINTN normbank, UINT16 bm)
{
    SBCStatus       ret = SBCOK;
    EFI_STATUS      retval = EFI_SUCCESS;
    EFI_HANDLE      *hndl = NULL;
    UINT16          *fblpath = EFI_BOOT_SSBL_PATH;
    //UINT16          *fblpath = L"\\boot\\vmlinuz-5.14.0-284.11.1.el9_2.x86_64" ;
    UINT8           *infostart = NULL;
    UINT32          last_of_fsbl = 0;
    UINT32          bsinfolen = 0;
    fsbl_bsinfo_t   bsinfo; 
    UINT32          bsptrcnt = 0;
    UINT8           HashValue[256];
    UINT32          HashSize =0;
    UINT32          fsbl_len =0;
    VOID            *EcPubKey = NULL;
    UINTN           HandleCount;

    LV_t            rdlv = {
            .length = 0,
            .value = NULL
      };

    HandleCount  = SBC_FindEfiFileSystemProtocol(&hndl);

    ret = SBC_GetFileSize(fblpath, (UINTN *)&rdlv.length);
    if (ret != SBCOK) {
      goto errdone;
    }

    rdlv.value = AllocateZeroPool((UINTN)rdlv.length);
    if (rdlv.value == NULL) {
      eprint("FSBL Verify Allocate Pool fail");
      ret = SBCNULLP;
      goto errdone;
    }

    ret = SBC_FindFileBufHndl(fblpath, &HandleCount, (VOID **)hndl);
    SBC_RET_VALIDATE_ERRCODEMSG((ret == SBCOK), ret, "File not found");

    dprint("SSBL File Handle Index : %d", HandleCount);

    retval = SBC_ReadFile(hndl[HandleCount], fblpath, &rdlv);
    if (EFI_ERROR(retval)) {
      eprint("%s filr read fail : %r", fblpath, retval);
      ret = SBCIO;
      goto errdone;
    }

    last_of_fsbl = rdlv.length - FSBL_BNIFO_SIZE;
    infostart = &((UINT8 *)rdlv.value)[last_of_fsbl];

    ZeroMem((void *)&bsinfo, sizeof bsinfo);

    CopyMem((void *)&bsinfo, (void *)infostart, sizeof bsinfo);

    //SBC_external_mem_print_bin("BSINFO", (UINT8 *)&bsinfo, sizeof bsinfo);

    dprint("----------- SSBL Boot Service Informmtion ------------");
    dprint("Signature Len     : %d", bsinfo.m.siglen );
    dprint("Firmware Info Len : %d", bsinfo.m.fwinfolen );
    dprint("Certificate Len   : %d", bsinfo.m.certlen );
    dprint("BaseAnswer Len    : %d", bsinfo.m.banswlen );
    dprint("BSinfo verdion    : %d", bsinfo.m.bsinfv );
    dprint("Spec.1 Value      : %d", bsinfo.m.reserv1 );
    dprint("Spec.2 Value      : %d", bsinfo.m.reserv2 );

    bsinfolen = bsinfo.m.siglen + bsinfo.m.fwinfolen + bsinfo.m.certlen  + bsinfo.m.banswlen;

      
    fsbl_len =  last_of_fsbl = rdlv.length - FSBL_BNIFO_SIZE - bsinfolen;
    //fsbl_len = last_of_fsbl - bsinfo.m.siglen;
    infostart = &((UINT8 *)rdlv.value)[last_of_fsbl];

    //dprint("FSBL Last : %d", last_of_fsbl);
    //SBC_external_mem_print_bin("Addtional Information", infostart,bsinfolen  );

    fsbl_bsinfo_ptr_t info = {NULL, NULL, NULL, NULL};

    info.baseansw = (VOID *)&infostart[bsptrcnt];
    bsptrcnt += bsinfo.m.banswlen;

    //SBC_external_mem_print_bin("Base Answer", (UINT8 *)info.baseansw,  bsinfo.m.banswlen );

    info.fwinfo = (VOID *)&infostart[bsptrcnt];
    bsptrcnt += bsinfo.m.fwinfolen;

    //SBC_external_mem_print_bin("FW Info", (UINT8 *)info.fwinfo,  bsinfo.m.fwinfolen );

    info.certi = (VOID *)&infostart[bsptrcnt];
    bsptrcnt += bsinfo.m.certlen;

    //SBC_external_mem_print_bin("Certificate", (UINT8 *)info.certi,  bsinfo.m.certlen );

    info.signature = (VOID *)&infostart[bsptrcnt];
    bsptrcnt += bsinfo.m.siglen;

    //SBC_external_mem_print_bin("Signature", (UINT8 *)info.signature,  bsinfo.m.siglen );

    // Verify the SSBL certificate using RootCA certificate
    // Later not comment 
    ret = SBC_FSBLIntgCheck(NULL , 
                            blkhnd, 
                            info.certi, 
                            bsinfo.m.certlen, 
                            normbank, 
                            bm);
    SBC_RET_VALIDATE_ERRCODEMSG((ret == SBCOK), ret, "SSBL certificate validation fail");


    BOOLEAN retbool = TRUE;
    //SBC_external_mem_print_bin("SSBL Certi.", (UINT8  *)info.certi, (UINTN)bsinfo.m.certlen);


    retbool = EcGetPublicKeyFromX509((CONST UINT8  *)info.certi, (UINTN)bsinfo.m.certlen,  &EcPubKey);

    if (retbool != TRUE) {
      eprint("EcGetPublicKeyFromX509 fail");
      ret = SBCFAIL;
      goto errdone;
    }

    fsbl_len += (bsinfo.m.fwinfolen + bsinfo.m.certlen  + bsinfo.m.banswlen);

    //dprint("SSBL image len : %d", fsbl_len);
    HashSize = 32;
    ret = SBC_HashCompute(
                         NULL, /* Not yet used */
                         rdlv.value,
                         fsbl_len,
                         HashValue
                      ) ; 


    //SBC_external_mem_print_bin("SSBL Image Hash", (UINT8 *)HashValue,   HashSize);

   

    retbool = EcDsaVerify(
        EcPubKey,
        CRYPTO_NID_SHA256,
        HashValue,
        HashSize,
        info.signature,
        bsinfo.m.siglen
        );

    if (retbool != TRUE) {
      sbc_err_sysprn(SBC_LOG_CMN_PRIO_ERR, 2,
           L"SBC",
           SYS_LOG_APP_NAME,
           SYS_LOG_CSC_NAME,
           8,
           SYS_LOG_EVT_DETECTION,
           L"SBC_tamper_SSBL signature verification faied");
      ret = SBCFAIL;
      goto errdone;
    }

    //sbc_err_sysprn(SBC_LOG_CMN_PRIO_INFO, 2, L"SBC", L"FSBL", L"CSC-01", 23, L"VERIFY", L"FSBL Integrate check is Done\n");
    //Print(L"FSBL Verify Success !!!\n");

    ((LV_t *)ansr)->value = AllocateZeroPool(bsinfo.m.banswlen);
    if (((LV_t *)ansr)->value == NULL) {
      //sbc_err_sysprn(SBC_LOG_CMN_PRIO_INFO, 2, L"SBC", L"FSBL", L"CSC-01", 23, L"VERIFY", L"FSBL Integrate check is Done\n");
      eprint("Base Answer buffer allocate fail");
      ret = SBCNULLP;
      goto errdone;
    }

    ((LV_t *)ansr)->length = bsinfo.m.banswlen;
    CopyMem(((LV_t *)ansr)->value, info.baseansw, bsinfo.m.banswlen);

//    switch (bootmode) {
//    case BOOT_MODE_FACTORY:
//      break;
//    default:
//      // Base Answer Validate
//      ret = SBC_BaseAnswerValidate(blkhnd, (UINT8 *)info.baseansw, bsinfo.m.banswlen );
////    switch (ret) {
////    case SBCBSANSWNOTFND:
////      ((LV_t *)ansr)->value = AllocateZeroPool(bsinfo.m.banswlen);
////      if (((LV_t *)ansr)->value == NULL) {
////        ret = SBCNULLP;
////       dprint("Base Answer object create fail \n");
////        goto errdone;
////      }
////      CopyMem(((LV_t *)ansr)->value, info.baseansw, bsinfo.m.banswlen);
////      //goto errdone;
////      break;
////    case SBCOK:
////      break;
////    default:
////      goto errdone;
////      break;
////    }
//      break;
//    }






    //ret = SBCOK;

errdone:

    if (EcPubKey != NULL) {
      EcFree(EcPubKey);
    }
    if (rdlv.value != NULL) {
      FreePool(rdlv.value);
      rdlv.value = NULL;

    }

//  if (ret != SBCOK) {
//      sbc_err_sysprn(SBC_LOG_CMN_PRIO_INFO, 2, L"SBC", L"FSBL", L"CSC-01", 23, L"VERIFY", L"SSBL Integrate check is Fail\n");
//  }
    return ret;

}

#ifdef _KERNEL_VERIFY_
SBCStatus  SBC_Kernel_Verify(VOID *handle)
{
    SBCStatus       ret = SBCOK;
    //EFI_STATUS      retval = EFI_SUCCESS;
    //EFI_HANDLE      *hndl = NULL;
    //UINT16          *fblpath = EFI_BOOT_SSBL_PATH;
    //UINT16          *fblpath = L"\\boot\\vmlinuz-5.14.0-284.11.1.el9_2.x86_64" ;
    UINT8           *infostart = NULL;
    UINT32          last_of_fsbl = 0;
    UINT32          bsinfolen = 0;
    fsbl_bsinfo_t   bsinfo; 
    UINT32          bsptrcnt = 0;
    UINT8           HashValue[256];
    UINT32          HashSize =0;
    UINT32          fsbl_len =0;
    VOID            *EcPubKey = NULL;
    //UINTN           HandleCount;

    boot_proc_t     *ctx = (boot_proc_t *)handle;

    LV_t            rdlv = {
            .length = 0,
            .value = NULL
    };

    ret = SBC_EFI_Kernel_Load(ctx->ldhndl, &rdlv);
    if (ret != SBCOK) {
      sbc_err_sysprn(SBC_LOG_CMN_PRIO_ERR, 2,
           SYS_LOG_HOST_BOOT,
           SYS_LOG_APP_NAME,
           SYS_LOG_CSC_NAME,
           8,
           SYS_LOG_EVT_DETECTION,
           L"SBC_VENDOR_SP Failed to the Kernel image load");

      goto errdone;
    }

    last_of_fsbl = rdlv.length - FSBL_BNIFO_SIZE;
    infostart = &((UINT8 *)rdlv.value)[last_of_fsbl];

    ZeroMem((void *)&bsinfo, sizeof bsinfo);

    CopyMem((void *)&bsinfo, (void *)infostart, sizeof bsinfo);

    //SBC_external_mem_print_bin("BSINFO", (UINT8 *)&bsinfo, sizeof bsinfo);

    dprint("----------- Kernel Boot Service Informmtion ------------");
    dprint("Signature Len     : %d", bsinfo.m.siglen );
    dprint("Firmware Info Len : %d", bsinfo.m.fwinfolen );
    dprint("Certificate Len   : %d", bsinfo.m.certlen );
    dprint("BaseAnswer Len    : %d", bsinfo.m.banswlen );
    dprint("BSinfo verdion    : %d", bsinfo.m.bsinfv );
    dprint("Spec.1 Value      : %d", bsinfo.m.reserv1 );
    dprint("Spec.2 Value      : %d", bsinfo.m.reserv2 );

    bsinfolen = bsinfo.m.siglen + bsinfo.m.fwinfolen + bsinfo.m.certlen  + bsinfo.m.banswlen;

      
    fsbl_len =  last_of_fsbl = rdlv.length - FSBL_BNIFO_SIZE - bsinfolen;
    //fsbl_len = last_of_fsbl - bsinfo.m.siglen;
    infostart = &((UINT8 *)rdlv.value)[last_of_fsbl];

    //dprint("FSBL Last : %d", last_of_fsbl);
    //SBC_external_mem_print_bin("Addtional Information", infostart,bsinfolen  );

    fsbl_bsinfo_ptr_t info = {NULL, NULL, NULL, NULL};

    info.baseansw = (VOID *)&infostart[bsptrcnt];
    bsptrcnt += bsinfo.m.banswlen;

    //SBC_external_mem_print_bin("Base Answer", (UINT8 *)info.baseansw,  bsinfo.m.banswlen );

    info.fwinfo = (VOID *)&infostart[bsptrcnt];
    bsptrcnt += bsinfo.m.fwinfolen;

    //SBC_external_mem_print_bin("FW Info", (UINT8 *)info.fwinfo,  bsinfo.m.fwinfolen );

    info.certi = (VOID *)&infostart[bsptrcnt];
    bsptrcnt += bsinfo.m.certlen;

    //SBC_external_mem_print_bin("Certificate", (UINT8 *)info.certi,  bsinfo.m.certlen );

    info.signature = (VOID *)&infostart[bsptrcnt];
    bsptrcnt += bsinfo.m.siglen;

    //SBC_external_mem_print_bin("Signature", (UINT8 *)info.signature,  bsinfo.m.siglen );

    // Verify the SSBL certificate using RootCA certificate
    // Later not comment 
//  ret = SBC_FSBLIntgCheck(NULL ,
//                          ctx->blkhnd,
//                          info.certi,
//                          bsinfo.m.certlen,
//                          ctx->curr_sw_bnk,
//                          ctx->bm);
//  SBC_RET_VALIDATE_ERRCODEMSG((ret == SBCOK), ret, "SSBL certificate validation fail");
//

    BOOLEAN retbool = TRUE;
    //SBC_external_mem_print_bin("SSBL Certi.", (UINT8  *)info.certi, (UINTN)bsinfo.m.certlen);


    retbool = EcGetPublicKeyFromX509((CONST UINT8  *)info.certi, (UINTN)bsinfo.m.certlen,  &EcPubKey);

    if (retbool != TRUE) {
      eprint("EcGetPublicKeyFromX509 fail");
      ret = SBCFAIL;
      goto errdone;
    }

    fsbl_len += (bsinfo.m.fwinfolen + bsinfo.m.certlen  + bsinfo.m.banswlen);

    //dprint("SSBL image len : %d", fsbl_len);
    HashSize = 32;
    ret = SBC_HashCompute(
                         NULL, /* Not yet used */
                         rdlv.value,
                         fsbl_len,
                         HashValue
                      ) ; 

    SBC_external_mem_print_bin("Kernel Hash", (UINT8 *)HashValue,   HashSize);

    retbool = EcDsaVerify(
        EcPubKey,
        CRYPTO_NID_SHA256,
        HashValue,
        HashSize,
        info.signature,
        bsinfo.m.siglen
        );

    if (retbool != TRUE) {
      sbc_err_sysprn(SBC_LOG_CMN_PRIO_ERR, 2,
           SYS_LOG_HOST_BOOT,
           SYS_LOG_APP_NAME,
           SYS_LOG_CSC_NAME,
           8,
           SYS_LOG_EVT_DETECTION,
           L"SBC_tamper_SSBL Failed to the OS signagure verify");
      ret = SBCFAIL;
      goto errdone;
    }

    sbc_err_sysprn(SBC_LOG_CMN_PRIO_INFO, 2,
           SYS_LOG_HOST_BOOT,
           SYS_LOG_APP_NAME,
           SYS_LOG_CSC_NAME,
           8,
           SYS_LOG_EVT_DETECTION,
           L"SBC_tamper_SSBL Successed the OS Signature verify");

errdone:

    if (EcPubKey != NULL) {
      EcFree(EcPubKey);
    }
    if (rdlv.value != NULL) {
      FreePool(rdlv.value);
      rdlv.value = NULL;

    }

//  if (ret != SBCOK) {
//      sbc_err_sysprn(SBC_LOG_CMN_PRIO_INFO, 2, L"SBC", L"FSBL", L"CSC-01", 23, L"VERIFY", L"SSBL Integrate check is Fail\n");
//  }
    return ret;

}
#endif

SBCStatus SBC_EFI_SSBL_Load_blk(VOID *blkhnd, LV_t *lv,  UINTN normbank, UINTN bm)
{

    SBCStatus           ret = SBCOK;

    UINTN               bsofs = 0; // Boot Sector Offset
    //UINTN               startlba = 0;

    UINT32          imglen = SBC_RAWPRT_DFLT_BLK_SZ;
    //UINT8           imghdr[SBC_RAWPRT_DFLT_BLK_SZ] = {0, };

    if (bm != BOOT_MODE_FACTORY) {
        dprint("Find the Old SSBL in the %d boot mode with Image banke %ld", 
               bm, normbank);
        
      bsofs = (BOOT_SECTOR1_OFS | ((normbank - 1) << SBC_BOOTFW_BKN_OFS));
      bsofs += BOOT_SSBL_OFS;
      //startlba = ((bsofs | BOOT_SSBL_OFS) >> SBC_RAWPRT_DFLT_SHIFT);
    }
    else {
        dprint("Find the Old SSBL in the Factory with Image banke %ld", normbank);
      bsofs = BOOT_SECTOR3_OFS;
      bsofs += BOOT_SSBL_OFS;
      //startlba = ((bsofs | BOOT_SSBL_OFS) >> SBC_RAWPRT_DFLT_SHIFT);
    }

    dprint("BSOFS:  0x%lx, StartLBA: %lu", bsofs, 0);

    ret = SBC_RawAlignedReadBlockIO(blkhnd, 
                                    bsofs,
                                    4,
                                    &imglen);
                                    //(void *)imghdr, &imglen, startlba);
    if (ret != SBCOK) {
        eprint("SSBL Factory Block Read Fail (%r)\n",ret);
        goto errdone;
    }

    dprint("Read image length : %ld", imglen);
    //CopyMem((void *)&imglen, &imghdr[0], sizeof imglen);

    // If imglen is zero, assumed that image not existense in Raw partition
    if (imglen <= 0) {
      eprint("Boot Mode (%d) Image not existense", bm);
      ret = SBCZEROL;
      goto errdone;
    }
    //dprint("SSBL image len : %ld", imglen);
    //imglen = ALIGN_VALUE(imglen, SBC_RAWPRT_DFLT_BLK_SZ);





    //dprint("Align SSBL image len : %ld", imglen);


    lv->value = AllocatePool(imglen);
    SBC_RET_VALIDATE_ERRCODEMSG((lv->value != NULL), SBCNULLP, "Allocate Memory Fail");

    ret = SBC_RawAlignedReadBlockIO(blkhnd,
                                    bsofs + 4,
                                    imglen,
                                    lv->value);
    SBC_RET_VALIDATE_ERRCODEMSG((ret == SBCOK), ret, "SSBL image read fail");


    //lv->length = imglen - FSBL_BNIFO_SIZE;
    // skip the image header ( for Length )
    //lv->value += 4;

    lv->length = imglen;


errdone:

    return ret;

}

SBCStatus SBC_GenDeviceID(UINT8 *devid)
{
    SBCStatus ret = SBCOK;
    //at_key_t key;
    LV_t    rdlv = {
        .value = NULL,
        .length = 0
    };
    
    hw_uniqueinfo_t info;
    UINT8 *computebuf = NULL;
    UINTN cnt = 0;

    UINT8 devidhsah[SBC_AT_HASH_LEN] = {0,};

    SBC_RET_VALIDATE_ERRCODEMSG((devid != NULL),SBCNULLP, "Out buffer Nill");

   


    // TODO : read the device information 
    ZeroMem((void *)&info, sizeof info);


    dprint("*** HW Unique Information Load --->");
    _baseboard_sn(&info);
//  SBC_external_mem_print_bin("BaseBoard SN", info.mbsn,info.mbsnl);
    SBC_mem_print_bin("BaseBoard SN", info.mbsn,info.mbsnl);

    _memorydevice_sn(&info);
//  SBC_external_mem_print_bin("MemoryDevice SN", info.mmsn, info.mmsnl);
    SBC_mem_print_bin("MemoryDevice SN", info.mmsn, info.mmsnl);

    _nvme_get_serial(&info);
//  SBC_external_mem_print_bin("NVME SN", info.nvmesn,info.nvmesnl);
    SBC_mem_print_bin("NVME SN", info.nvmesn,info.nvmesnl);

    //_read_fsbl_image(&rdlv);
    SBC_EFI_FSBL_Load(&rdlv);
    SBC_RET_VALIDATE_ERRCODEMSG((rdlv.value != NULL), SBCNULLP, "FSBL read fail");

    ret = SBC_HashCompute(
                         NULL, /* Not yet used */
                         rdlv.value,
                         rdlv.length,
                         devidhsah
                      ) ; 

    if (ret != SBCOK) {
      eprint("FSBL Hash compute fail \n");
      goto errdone;
    }


    rdlv.length = SBC_AT_HASH_LEN;

    computebuf = AllocatePool(info.mbsnl + info.mmsnl + info.nvmesnl + rdlv.length);
    SBC_RET_VALIDATE_ERRCODEMSG((computebuf != NULL),SBCNULLP, "Compute buffer Nill");

    cnt = 0;
    //Print(L" cnt : %d \n", cnt);
    CopyMem((void *)&computebuf[0], info.mbsn, info.mbsnl);
    cnt = info.mbsnl;

    //Print(L"Next cnt : %d \n", cnt);
    CopyMem((void *)&computebuf[cnt], info.mmsn, info.mmsnl);
    cnt += info.mmsnl;

    //Print(L"Next Next cnt : %d \n", cnt);
    CopyMem((void *)&computebuf[cnt], info.nvmesn, info.nvmesnl);
    cnt += info.nvmesnl;

        //Print(L"Next Next cnt : %d \n", cnt);
    CopyMem((void *)&computebuf[cnt], devidhsah, rdlv.length);
    cnt += rdlv.length;

    //dprint("DICE message length  : %d", cnt);
    //dprint("DICE message length  : %d \n", cnt);
    //SBC_mem_print_bin("Device ID Raw Fmt", computebuf, cnt);
    ret = SBC_HashCompute(
                             NULL, /* Not yet used */
                             computebuf,
                             cnt,
                             devid
                          ) ;

    if (ret != SBCOK) {
      eprint("Device Dice Message Hash compute fail \n");
      goto errdone;
    }

    SBC_mem_print_bin("Device ID", devid, 32);
    ZeroMem(print_out_key, 32);
    ZeroMem(mrgmsg, sizeof mrgmsg);
    SBC_LogHexToStrChar16(devid, 32, print_out_key, sizeof(print_out_key)/sizeof(print_out_key[0]),  FALSE, 0);

    ///SBC_mem_print_bin("Print out key", (UINT8 *)print_out_key, sizeof print_out_key);

    dprint("*** Unique Information Combination --->");
    UnicodeSPrint(mrgmsg,  sizeof mrgmsg, L"SBC_Dice_DEVID Creation Succeess (%s) \n", print_out_key);


    sbc_err_sysprn(SBC_LOG_CMN_PRIO_INFO, 2, 
              SYS_LOG_HOST_BOOT, 
              SYS_LOG_APP_NAME, 
              SYS_LOG_CSC_NAME, 
              1, 
              L"Validation ", 
              mrgmsg);
    
errdone:

    if (ret != SBCOK) {
        sbc_err_sysprn(SBC_LOG_CMN_PRIO_ERR, 2, 
              SYS_LOG_HOST_BOOT, 
              SYS_LOG_APP_NAME, 
              SYS_LOG_CSC_NAME, 
              1, 
              L"Validation ", 
              L"SBC_Dice_DEVID Creation Fail");
    }

    if(computebuf) {
        FreePool(computebuf);
    }
    return ret;

}

SBCStatus SBC_GenFWIDOld(EFI_HANDLE *h_image, UINT8 *devid, UINT8 *fwid, UINTN normbank, UINTN bm)
{

  SBCStatus ret       = SBCOK;
  UINT8 *temp = NULL;
  //UINT8 *rdbuf = NULL;
  LV_t lv;
  UINT8 hash_ssbl[SBC_AT_HASH_LEN] = {0, };


  lv.value = NULL;
  lv.length = 0;

  ret = SBC_EFI_SSBL_Load_blk(h_blkio, &lv, normbank, bm);
  SBC_RET_VALIDATE_ERRCODEMSG((ret == SBCOK), ret, "SSB Image load fail");
  SBC_RET_VALIDATE_ERRCODEMSG((lv.length > 0), SBCZEROL, "SSB Image length 0");

//lv.value = hash_ssbl;
//lv.length = SBC_AT_HASH_LEN;

  // Added the Hash for SSBL
  ret = SBC_HashCompute( NULL, 
                         lv.value,
                         lv.length,
                         hash_ssbl );
  SBC_RET_VALIDATE_ERRCODEMSG((ret == SBCOK), ret, "SSBL hash compute failed");

  //dprint("ssbl image load len : %ld", lv.length);
  //SBC_mem_print_bin("SSBL image", (UINT8 *)lv.value, lv.length);
  SBC_mem_print_bin("ssbl hash", (UINT8 *)hash_ssbl, 32);



  temp = AllocateZeroPool(SBC_AT_HASH_LEN << 1);
  if (temp == NULL) {
    sbc_err_sysprn(SBC_LOG_CMN_PRIO_ERR, 2,
          SYS_LOG_HOST_BOOT, 
          SYS_LOG_APP_NAME, 
          SYS_LOG_CSC_NAME, 
          0, 
          L"Detection ", 
          L"SBC_Vendor Not enough resource \n");
    goto errdone;
  }

  CopyMem((void *)&temp[0], devid, SBC_AT_HASH_LEN);
  CopyMem((void *)&temp[SBC_AT_HASH_LEN], hash_ssbl, SBC_AT_HASH_LEN);

  ret = SBC_HashCompute(
                             NULL, /* Not yet used */
                             temp,
                             SBC_AT_HASH_LEN << 1,
                             fwid
                          ) ;

  ZeroMem(print_out_key, 32);
  ZeroMem(mrgmsg, sizeof mrgmsg);
  SBC_LogHexToStrChar16(fwid, 32, print_out_key, sizeof(print_out_key)/sizeof(print_out_key[0]),  FALSE, 0);

  //SBC_mem_print_bin("Print out key", (UINT8 *)print_out_key, sizeof print_out_key);

  UnicodeSPrint(mrgmsg,  sizeof mrgmsg, L"SBC_Dice_FWID Old Creation Succeess (%s) \n", print_out_key);

  //SBC_LogHexKeyConvToChar16(mrgmsg, (VOID *)print_msg, fwid);


  sbc_err_sysprn(SBC_LOG_CMN_PRIO_INFO, 2, 
          SYS_LOG_HOST_BOOT, 
          SYS_LOG_APP_NAME, 
          SYS_LOG_CSC_NAME, 
          1, 
          L"Validation ", 
          mrgmsg);
errdone:

    if (ret != SBCOK) {
        sbc_err_sysprn(SBC_LOG_CMN_PRIO_ERR, 2, 
              SYS_LOG_HOST_BOOT, 
              SYS_LOG_APP_NAME, 
              SYS_LOG_CSC_NAME, 
              1, 
              L"Validation ", 
              L"SBC_Dice_FWID Creation Fail");
    }



  if (temp != NULL) {
    FreePool(temp);
  }

  if (lv.value != NULL) {
    //FreePool(lv.value);
  }
  return ret;


}


SBCStatus  SBC_DiceKeysGenOld(EFI_HANDLE ImageHandle, VOID *p,UINTN normbank, UINTN bm)
{
    SBCStatus ret = SBCOK;
    atp_ident_t *h = NULL;

    h = (atp_ident_t *)p;

    dprint("Old OSID Key Gen");
    ret = SBC_GenDeviceID(h->devid);
    if (ret != SBCOK) {
        dprint("Device ID generate fail \n");
        goto errdone;
    }

    //SBC_mem_print_bin("Device ID", h->devid, sizeof h->devid);SBC_mem_print_bin("Device ID", h->devid, sizeof h->devid);




    ret = SBC_GenFWIDOld(ImageHandle, h->devid, h->fwid, normbank, bm);
    if (ret != SBCOK) {
        dprint("FW ID generate fail \n");
        goto errdone;
    }

    //SBC_mem_print_bin("Firmware ID", h->fwid, sizeof h->fwid);

    ret = SBC_GenOSID(ImageHandle,  h->fwid, h->osid);
    if (ret != SBCOK) {
        dprint("FW ID generate fail \n");
        goto errdone;
    }

    //SBC_mem_print_bin("Firmware ID", h->fwid, sizeof h->fwid);
    ret = SBCOK;

errdone:
    return ret;

}

SBCStatus SBC_GenFWID(VOID  *priv, UINT8 *devid, UINT8 *fwid, UINTN normbank, UINTN bm)
{

  SBCStatus ret       = SBCOK;
  UINT8 *temp = NULL;
  //UINT8 *rdbuf = NULL;
  LV_t lv;
  UINT8 hash_ssbl[SBC_AT_HASH_LEN] = {0, };
  //CHAR16 *print_msg = L"SBC_Dice_FWID Creation Succeess (%s) \n";


  lv.value = NULL;
  lv.length = 0;

  //
  // EFI_HANDLE parameter don't need 
  // 
  ret = SBC_EFI_SSBL_Load(NULL, &lv);
  SBC_RET_VALIDATE_ERRCODEMSG((ret == SBCOK), ret, "SSB Image load fail");
  SBC_RET_VALIDATE_ERRCODEMSG((lv.length > 0), SBCZEROL, "SSB Image length 0");

  //lv.value = hash_ssbl;
  //lv.length = SBC_AT_HASH_LEN;

  // Added the Hash for SSBL
  ret = SBC_HashCompute( NULL, 
                         lv.value,
                         lv.length,
                         hash_ssbl );
  SBC_RET_VALIDATE_ERRCODEMSG((ret == SBCOK), ret, "SSBL hash compute failed");

  SBC_mem_print_bin("SSBL Hash", hash_ssbl, 32);

  temp = AllocateZeroPool(SBC_AT_HASH_LEN << 1);
  SBC_RET_VALIDATE_ERRCODEMSG((temp != NULL), SBCNULLP, "memeory creation fail");

  CopyMem((void *)&temp[0], devid, SBC_AT_HASH_LEN);
  CopyMem((void *)&temp[SBC_AT_HASH_LEN], hash_ssbl, SBC_AT_HASH_LEN);

  ret = SBC_HashCompute(
                             NULL, /* Not yet used */
                             temp,
                             SBC_AT_HASH_LEN << 1,
                             fwid
                          ) ;

  SBC_mem_print_bin("FW ID", fwid, 32);

  ZeroMem(print_out_key, 32);
  ZeroMem(mrgmsg, sizeof mrgmsg);
  SBC_LogHexToStrChar16(fwid, 32, print_out_key, sizeof(print_out_key)/sizeof(print_out_key[0]),  FALSE, 0);

  //SBC_mem_print_bin("Print out key", (UINT8 *)print_out_key, sizeof print_out_key);

  UnicodeSPrint(mrgmsg,  sizeof mrgmsg, L"SBC_Dice_FWID Creation Succeess (%s) \n", print_out_key);

  //SBC_LogHexKeyConvToChar16(mrgmsg, (VOID *)print_msg, fwid);


  sbc_err_sysprn(SBC_LOG_CMN_PRIO_INFO, 2, 
          SYS_LOG_HOST_BOOT, 
          SYS_LOG_APP_NAME, 
          SYS_LOG_CSC_NAME, 
          1, 
          L"Validation ", 
          mrgmsg);
errdone:

  //dprint();
  if (temp != NULL) {
    //dprint();
    FreePool(temp);
  }

  if (lv.value != NULL) {
    //dprint();
    //FreePool(lv.value);
  }
  //dprint();
  return ret;


}


SBCStatus SBC_GenOSID(EFI_HANDLE *h_image, UINT8 *fwid, UINT8 *osid)
{
  SBCStatus ret       = SBCOK;
  UINT8 *temp = NULL;
  [[gnu::unused]]UINT8 *rdbuf = NULL;
  LV_t lv;

  UINT8 os_hash[SBC_AT_HASH_LEN] = {0, };

#ifdef _TEST_ERROR_SET_    
    if (NvramErr_IsTrue(ERR_OSID_KEY)) {
        sbc_err_sysprn(SBC_LOG_CMN_PRIO_INFO, 2,
                 SYS_LOG_HOST_BOOT,
                 SYS_LOG_APP_NAME,
                 SYS_LOG_CSC_NAME,
                 0,
                 SYS_LOG_EVT_DETECTION,
                 L"SBC_VENDOR_SP Fail to create the OSID");
        ret = SBCFAIL;
        goto errdone;
    }
#endif
  lv.value = NULL;
  lv.length = 0;

  // OS Kernel Image read 
  ret = SBC_EFI_Kernel_Load(h_image, &lv);
  if (ret != SBCOK) {
    dprint("Kernel Image load fail \n");
    sbc_err_sysprn(SBC_LOG_CMN_PRIO_ERR, 2,
          SYS_LOG_HOST_BOOT, 
          SYS_LOG_APP_NAME, 
          SYS_LOG_CSC_NAME, 
          1, 
          L"Detection ", 
          L"SBC_SP_FILE_RD OS File Not Found \n");
    goto errdone;
  }


    // Added the Hash for SSBL
  ret = SBC_HashCompute( NULL, 
                         lv.value,
                         lv.length,
                         os_hash );

  if ( ret != SBCOK) {
    sbc_err_sysprn(SBC_LOG_CMN_PRIO_ERR, 2,
          SYS_LOG_HOST_BOOT, 
          SYS_LOG_APP_NAME, 
          SYS_LOG_CSC_NAME, 
          0, 
          L"Detection ", 
          L"SBC_Vendor OS Hash Create Fail \n");
    goto errdone;
  }
  //SBC_RET_VALIDATE_ERRCODEMSG((ret == SBCOK), ret, "SSBL hash compute failed");

  temp = AllocateZeroPool(SBC_AT_HASH_LEN << 1);
  if (temp == NULL) {
    sbc_err_sysprn(SBC_LOG_CMN_PRIO_ERR, 2,
          SYS_LOG_HOST_BOOT, 
          SYS_LOG_APP_NAME, 
          SYS_LOG_CSC_NAME, 
          0, 
          L"Detection ", 
          L"SBC_Vendor Not enough resource \n");
    goto errdone;
  }
  //SBC_RET_VALIDATE_ERRCODEMSG((temp != NULL), SBCNULLP, "memeory creation fail");

  CopyMem((void *)&temp[0], fwid, SBC_AT_HASH_LEN);
  CopyMem((void *)&temp[SBC_AT_HASH_LEN], os_hash,  SBC_AT_HASH_LEN);

  ret = SBC_HashCompute(
                             NULL, /* Not yet used */
                             temp,
                             SBC_AT_HASH_LEN << 1,
                             osid
                          ) ;

  if (ret != SBCOK) {
        sbc_err_sysprn(SBC_LOG_CMN_PRIO_ERR, 2,
          SYS_LOG_HOST_BOOT, 
          SYS_LOG_APP_NAME, 
          SYS_LOG_CSC_NAME, 
          0, 
          L"Detection ", 
          L"SBC_Vendor OSID compute Fail \n");

        goto errdone;
  }

  SBC_mem_print_bin("OS ID", osid, 32);

  ZeroMem(print_out_key, 32);
  ZeroMem(mrgmsg, sizeof mrgmsg);
  SBC_LogHexToStrChar16(osid, 32, print_out_key, sizeof(print_out_key)/sizeof(print_out_key[0]),  FALSE, 0);

  //SBC_mem_print_bin("Print out key", (UINT8 *)print_out_key, sizeof print_out_key);

  UnicodeSPrint(mrgmsg,  sizeof mrgmsg, L"SBC_Dice_OSID Creation Succeess (%s) \n", print_out_key);


  sbc_err_sysprn(SBC_LOG_CMN_PRIO_INFO, 2, 
          SYS_LOG_HOST_BOOT, 
          SYS_LOG_APP_NAME, 
          SYS_LOG_CSC_NAME, 
          1, 
          L"Validation ", 
          mrgmsg);
errdone:

  if (temp != NULL) {
    FreePool(temp);
  }

  if (lv.value != NULL) {
    FreePool(lv.value);
  }
  return ret;


}

#if 0
SBCStatus SBC_GenMigrationKey(void *priv, void *outmsg)
{
    SBCStatus ret = SBCOK;

    boot_proc_t *p = (boot_proc_t *)priv;

    UINTN msglen = 0UL;
    UINTN len_fsbl = 0UL;
    UINTN len_ssbl = 0UL;
    UINTN len_hwifno = 0UL;
    [[gnu::unused]] UINTN len_blkfsbl = 0UL;
    [[gnu::unused]] UINTN len_blkssbl = 0UL;
    UINT8 *msg = NULL;
    hw_uniqueinfo_t info;
    UINTN startaddr = 0;
    UINTN startlba = 0;
    boot_fw_inf_t *fwinf;
    UINTN imglen = 0;
    UINTN cpyofs = 0;

    UINT8 *fbuf = NULL;
    [[maybe_unused]] UINTN flen = 0UL;
    LV_t lv;

    EFI_HANDLE *f_hndl;
    UINT8 temp_hash[ATP_IDENT_KEY_STG] = {0, };
    

    SBC_RET_VALIDATE_ERRCODEMSG((p != NULL),
                               SBCNULLP,
                               "Invalid Parameter");


    // Get the Hardware Unique Information
    ZeroMem((void *)&info, sizeof info);

    _baseboard_sn(&info);
    _memorydevice_sn(&info);
    _nvme_get_serial(&info);

    len_hwifno = info.mbsnl + info.mmsnl + info.nvmesnl;
    msglen = len_hwifno;

    // Getting the FSBL and SSBL file size
    ret = SBC_GetFileSize(EFI_BOOT_FSBL_PATH, &len_fsbl);
    SBC_RET_VALIDATE_ERRCODEMSG((ret == SBCOK),
                               ret,
                               "Not Found the FSBL");

    ret = SBC_GetFileSize(EFI_BOOT_SSBL_PATH, &len_ssbl);
    SBC_RET_VALIDATE_ERRCODEMSG((ret == SBCOK),
                               ret,
                               "Not Found the SSBL");

    dprint("Existing FSBL (%d) & SSBL (%d) Length", len_fsbl, len_ssbl);

    msglen += (len_fsbl + len_ssbl);

    dprint();
    // Obtain the length for SSBL and FSBL in Raw-partition
    fwinf = AllocateZeroPool(sizeof(boot_fw_inf_t));
    SBC_RET_VALIDATE_ERRCODEMSG((fwinf != NULL),SBCNULLP, "Firmware Info Memory allocate Nill");

    dprint("Previously Bank ID : %d", p->pvs_sw_bnk - 1);
    //Step 2. Read Current Image and Hash compute
    //pvs_sw_bank means that "Previously Firware location"
    
    startaddr = (BOOT_SECTOR1_OFS | (BOOT_FW_IMGMAX *  (p->pvs_sw_bnk - 1)));
    startlba = (startaddr >> SBC_RAWPRT_DFLT_SHIFT);
    imglen = ALIGN_VALUE(sizeof *fwinf, SBC_RAWPRT_DFLT_BLK_SZ);

    dprint("Start Address : 0x%04x", startaddr);

    ret = SBC_RawPrtReadBlock(p->blkhnd, (void *)fwinf->value, (UINT32 *)&imglen, startlba);
    SBC_RET_VALIDATE_ERRCODEMSG((ret == SBCOK), ret, "Raw Partition read fail");

    dprint("FSBL len : %d , SSBL Length : %d \n", fwinf->mbr.fsbln, fwinf->mbr.ssbln);

    //
    // If previoulsy firmwrae not existense, it's compute using FACTORY image 
    //
    if (fwinf->mbr.fsbln == 0) {
        startaddr = BOOT_SECTOR3_OFS; //(BOOT_SECTOR1_OFS | (BOOT_FW_IMGMAX *  (p->pvs_sw_bnk - 1)));
        startlba = (startaddr >> SBC_RAWPRT_DFLT_SHIFT);
        imglen = ALIGN_VALUE(sizeof *fwinf, SBC_RAWPRT_DFLT_BLK_SZ);

        dprint("It's load from FACTORY bank because previously firmware is not existense");
        ret = SBC_RawPrtReadBlock(p->blkhnd, (void *)fwinf->value, (UINT32 *)&imglen, startlba);
        SBC_RET_VALIDATE_ERRCODEMSG((ret == SBCOK), ret, "Raw Partition read fail");

        dprint("Factory FSBL len : %d , SSBL Length : %d \n", fwinf->mbr.fsbln, fwinf->mbr.ssbln);
    }

    msglen += (fwinf->mbr.fsbln + fwinf->mbr.ssbln);

    msg = AllocateZeroPool(msglen);
    SBC_RET_VALIDATE_ERRCODEMSG((msg != NULL), SBCNULLP, "Not enough resource");


    CopyMem((void *)&msg[cpyofs], info.mbsn , info.mbsnl);
    cpyofs += info.mbsnl;

    CopyMem((void *)&msg[cpyofs], info.mmsn, info.mmsnl);
    cpyofs += info.mmsnl;

    CopyMem((void *)&msg[cpyofs], info.nvmesn, info.nvmesnl);
    cpyofs += info.nvmesnl;

    //
    // Read the FSBL file 
    //

    SBC_FindEfiFileSystemProtocol(&f_hndl);

    fbuf = AllocateZeroPool(len_fsbl);
    lv.value = fbuf;
    lv.length = len_fsbl;

    ret = SBC_ReadFile(f_hndl[0], EFI_BOOT_FSBL_PATH, &lv);
    SBC_RET_VALIDATE_ERRCODEMSG((ret == SBCOK), SBCNULLP, "FSBL File Reaed Fail");

    ret = SBC_HashCompute(NULL, lv.value, lv.length, temp_hash);
    SBC_RET_VALIDATE_ERRCODEMSG((ret == SBCOK), SBCNULLP, "FSBL File HASH Fail");

    SBC_mem_print_bin("FSBL File Hash", (UINT8 *)temp_hash, ATP_IDENT_KEY_STG);
    CopyMem((void *)&msg[cpyofs], temp_hash, ATP_IDENT_KEY_STG);
    cpyofs += ATP_IDENT_KEY_STG;

    if (fbuf != NULL) {
        //lv.value = NULL;
        FreePool(fbuf);
    }

    //
    // Read the SSBL flie
    //
    fbuf = AllocateZeroPool(len_ssbl);
    lv.value = fbuf;
    lv.length = len_ssbl;

    ret = SBC_ReadFile(f_hndl[0], EFI_BOOT_SSBL_PATH, &lv);
    SBC_RET_VALIDATE_ERRCODEMSG((ret == SBCOK), SBCNULLP, "SSBL File Reaed Fail");

    ZeroMem((void *)temp_hash, 32);
    ret = SBC_HashCompute(NULL, lv.value, lv.length, temp_hash);
    SBC_RET_VALIDATE_ERRCODEMSG((ret == SBCOK), SBCNULLP, "SSBL File HASH Fail");
    SBC_mem_print_bin("SSBL File Hash", (UINT8 *)temp_hash, ATP_IDENT_KEY_STG);
    CopyMem((void *)&msg[cpyofs], temp_hash, ATP_IDENT_KEY_STG);
    cpyofs += ATP_IDENT_KEY_STG;

    if (fbuf != NULL) {
        dprint();
        FreePool(fbuf);
        dprint();
    }
    dprint();


    //
    // Un-used FSBL  ( into the Raw-partiiont)
    //
    ret = SBC_HashCompute(NULL, fwinf->mbr.fsblimg, fwinf->mbr.fsbln, (void *)&msg[cpyofs]);
    SBC_mem_print_bin("Previously FSBL File Hash", (UINT8 *)&msg[cpyofs], ATP_IDENT_KEY_STG);
    SBC_RET_VALIDATE_ERRCODEMSG((ret == SBCOK), SBCNULLP, "Raw Partition FSBL HASH Fail");
    cpyofs += ATP_IDENT_KEY_STG;

    ret = SBC_HashCompute(NULL, fwinf->mbr.ssblimg, fwinf->mbr.ssbln, (void *)&msg[cpyofs]);
    SBC_mem_print_bin("Previously SSBL File Hash", (UINT8 *)&msg[cpyofs], ATP_IDENT_KEY_STG);
    SBC_RET_VALIDATE_ERRCODEMSG((ret == SBCOK), SBCNULLP, "Raw Partition SSBL File HASH Fail");
    cpyofs += ATP_IDENT_KEY_STG;



    //
    // Final message digest 
    // 
    ret = SBC_HashCompute(NULL, (UINT8 *)&msg[0], cpyofs, outmsg);
    SBC_RET_VALIDATE_ERRCODEMSG((ret == SBCOK), SBCNULLP, "Raw Partition SSBL File HASH Fail");
errdone:

    if (fwinf != NULL) {
        FreePool(fwinf);
    }

    if (msg != NULL) {
        FreePool(msg);
    }


    return ret;
}
#endif

SBCStatus SBC_GenMigrationKey(void *priv, void *outmsg)
{
    SBCStatus ret = SBCOK;

    boot_proc_t *p = (boot_proc_t *)priv;

    UINTN msglen = 0UL;
    UINTN len_fsbl = 0UL;
    UINTN len_ssbl = 0UL;
    UINTN len_hwifno = 0UL;
    [[gnu::unused]] UINTN len_blkfsbl = 0UL;
    [[gnu::unused]] UINTN len_blkssbl = 0UL;
    UINT8 *msg = NULL;
    hw_uniqueinfo_t info;
    UINTN startaddr = 0;
    UINTN startlba = 0;
    boot_fw_inf_t *fwinf;
    UINTN imglen = 0;
    UINTN cpyofs = 0;

    LV_t fsbl_lv;
    LV_t  ssbl_lv;
    

    UINT8 *fbuf = NULL;
    [[maybe_unused]] UINTN flen = 0UL;
    [[gnu::unused]]LV_t lv;

    EFI_HANDLE *f_hndl;
    UINT8 temp_hash[ATP_IDENT_KEY_STG] = {0, };

#ifdef _TEST_ERROR_SET_    
    if (NvramErr_IsTrue(ERR_MIGRATION_KEY)) {

        sbc_err_sysprn(SBC_LOG_CMN_PRIO_ERR, 
             2, 
             SYS_LOG_HOST_BOOT, 
             SYS_LOG_APP_NAME,SYS_LOG_CSC_NAME, 
             4, 
             SYS_LOG_EVT_DETECTION, 
             L"SBC_BootFW_Update Fail to MigrationKey Creation \n");

        ret = SBCFAIL;
        goto errdone;
    }
#endif

    SBC_RET_VALIDATE_ERRCODEMSG((p != NULL),
                               SBCNULLP,
                               "Invalid Parameter");


    // Get the Hardware Unique Information
    ZeroMem((void *)&info, sizeof info);

    _baseboard_sn(&info);
    _memorydevice_sn(&info);
    _nvme_get_serial(&info);

    len_hwifno = info.mbsnl + info.mmsnl + info.nvmesnl;
    msglen = len_hwifno;

    // Getting the FSBL and SSBL file size
    ret = SBC_GetFileSize(EFI_BOOT_FSBL_PATH, &len_fsbl);
    SBC_RET_VALIDATE_ERRCODEMSG((ret == SBCOK),
                               ret,
                               "Not Found the FSBL");

    ret = SBC_GetFileSize(EFI_BOOT_SSBL_PATH, &len_ssbl);
    SBC_RET_VALIDATE_ERRCODEMSG((ret == SBCOK),
                               ret,
                               "Not Found the SSBL");

    dprint("Existing FSBL (%d) & SSBL (%d) Length", len_fsbl, len_ssbl);

    msglen += (len_fsbl + len_ssbl);

    dprint();
    // Obtain the length for SSBL and FSBL in Raw-partition
    fwinf = AllocateZeroPool(sizeof(boot_fw_inf_t));
    SBC_RET_VALIDATE_ERRCODEMSG((fwinf != NULL),SBCNULLP, "Firmware Info Memory allocate Nill");

    dprint("Previously Bank ID : %d", p->pvs_sw_bnk - 1);
    dprint("Current Bank ID : %d", p->curr_sw_bnk - 1);
    //Step 2. Read Current Image and Hash compute
    //pvs_sw_bank means that "Previously Firware location"

    //startaddr = (BOOT_SECTOR1_OFS | (BOOT_FW_IMGMAX *  (p->pvs_sw_bnk - 1)));
    startaddr = (BOOT_SECTOR1_OFS | (BOOT_FW_IMGMAX *  (p->curr_sw_bnk - 1)));
    startlba = (startaddr >> SBC_RAWPRT_DFLT_SHIFT);
    imglen = ALIGN_VALUE(sizeof *fwinf, SBC_RAWPRT_DFLT_BLK_SZ);

    dprint("Start Address : 0x%04x", startaddr);

    ret = SBC_RawPrtReadBlock(p->blkhnd, (void *)fwinf->value, (UINT32 *)&imglen, startlba);
    SBC_RET_VALIDATE_ERRCODEMSG((ret == SBCOK), ret, "Raw Partition read fail");

    dprint("FSBL len : %d , SSBL Length : %d \n", fwinf->mbr.fsbln, fwinf->mbr.ssbln);

// Commented by Leon at 20251212
// From now on, use the prevmode in Raw-partition 
//  if (((fwinf->mbr.fsbln == 0) && (fwinf->mbr.ssbln == 0))) {
//      dprint("A. It's load from FACTORY bank because previously firmware is not existense");
//      p->is_factory = TRUE;
//  }

    // Added by Leon at 20251212

    dprint("===== Migration Key information ======");
    dprint("p->prevmode : \t %d", p->prevmode);
    dprint("p->bootst : \t 0x%lx", p->bootst);
    dprint("p->bm : \t %d", p->bm);
    if (p->prevmode == 0 &&
        ((p->bootst == SB_PROC_ST_ABNRAM && p->bm == BOOT_MODE_NORMAL) ||
         (p->bm == BOOT_MODE_UPDATE)))  {
        dprint("Read the image from Factory Bank because prev mode is 0");
        p->is_factory = TRUE;
    }

    if (p->prevmode == 0 && p->bm == BOOT_MODE_RECOVERY) {
        startaddr = (BOOT_SECTOR1_OFS | (BOOT_FW_IMGMAX *  (p->curr_sw_bnk - 1)));
        startlba = (startaddr >> SBC_RAWPRT_DFLT_SHIFT);
        imglen = ALIGN_VALUE(sizeof *fwinf, SBC_RAWPRT_DFLT_BLK_SZ);

        dprint("Start Address : 0x%04x", startaddr);

        ret = SBC_RawPrtReadBlock(p->blkhnd, (void *)fwinf->value, (UINT32 *)&imglen, startlba);
        SBC_RET_VALIDATE_ERRCODEMSG((ret == SBCOK), ret, "Raw Partition read fail");

        p->is_factory = FALSE;
    }
    //
    // If previoulsy firmwrae not existense, it's compute using FACTORY image 
    //
    //if (fwinf->mbr.fsbln == 0) {
    if (p->is_factory == TRUE) {
        startaddr = BOOT_SECTOR3_OFS; //(BOOT_SECTOR1_OFS | (BOOT_FW_IMGMAX *  (p->pvs_sw_bnk - 1)));
        startlba = (startaddr >> SBC_RAWPRT_DFLT_SHIFT);
        imglen = ALIGN_VALUE(sizeof *fwinf, SBC_RAWPRT_DFLT_BLK_SZ);

        dprint("B. It's load from FACTORY bank because previously firmware is not existense");
        ret = SBC_RawPrtReadBlock(p->blkhnd, (void *)fwinf->value, (UINT32 *)&imglen, startlba);
        SBC_RET_VALIDATE_ERRCODEMSG((ret == SBCOK), ret, "Raw Partition read fail");

        dprint("Factory FSBL len : %d , SSBL Length : %d \n", fwinf->mbr.fsbln, fwinf->mbr.ssbln);
    }

    msglen += (fwinf->mbr.fsbln + fwinf->mbr.ssbln);

    msg = AllocateZeroPool(msglen);
    SBC_RET_VALIDATE_ERRCODEMSG((msg != NULL), SBCNULLP, "Not enough resource");


    CopyMem((void *)&msg[cpyofs], info.mbsn , info.mbsnl);
    cpyofs += info.mbsnl;

    CopyMem((void *)&msg[cpyofs], info.mmsn, info.mmsnl);
    cpyofs += info.mmsnl;

    CopyMem((void *)&msg[cpyofs], info.nvmesn, info.nvmesnl);
    cpyofs += info.nvmesnl;

//  //
//  // Un-used FSBL  ( into the Raw-partiiont) - Currenrtly
//  //
//  ret = SBC_HashCompute(NULL, fwinf->mbr.fsblimg, fwinf->mbr.fsbln, (void *)&msg[cpyofs]);
//  SBC_mem_print_bin("Currently FSBL File Hash", (UINT8 *)&msg[cpyofs], ATP_IDENT_KEY_STG);
//  SBC_RET_VALIDATE_ERRCODEMSG((ret == SBCOK), SBCNULLP, "Raw Partition FSBL HASH Fail");
//  cpyofs += ATP_IDENT_KEY_STG;
//
//  ret = SBC_HashCompute(NULL, fwinf->mbr.ssblimg, fwinf->mbr.ssbln, (void *)&msg[cpyofs]);
//  SBC_mem_print_bin("Currently SSBL File Hash", (UINT8 *)&msg[cpyofs], ATP_IDENT_KEY_STG);
//  SBC_RET_VALIDATE_ERRCODEMSG((ret == SBCOK), SBCNULLP, "Raw Partition SSBL File HASH Fail");
//  cpyofs += ATP_IDENT_KEY_STG;

    //
    // Read the FSBL file 
    //

    SBC_FindEfiFileSystemProtocol(&f_hndl);

    fbuf = AllocateZeroPool(len_fsbl);
    lv.value = fbuf;
    lv.length = len_fsbl;

    if (p->bm == BOOT_MODE_UPDATE) {

        dprint("Migrattion Key Create by Update");

        //
        // Un-used FSBL  ( into the Raw-partiiont) - Currenrtly 
        //
        ret = SBC_HashCompute(NULL, fwinf->mbr.fsblimg, fwinf->mbr.fsbln, (void *)&msg[cpyofs]);
        SBC_mem_print_bin(" FSBL File Hash", (UINT8 *)&msg[cpyofs], ATP_IDENT_KEY_STG);
        SBC_RET_VALIDATE_ERRCODEMSG((ret == SBCOK), SBCNULLP, "Raw Partition FSBL HASH Fail");
        cpyofs += ATP_IDENT_KEY_STG;

        ret = SBC_HashCompute(NULL, fwinf->mbr.ssblimg, fwinf->mbr.ssbln, (void *)&msg[cpyofs]);
        SBC_mem_print_bin(" SSBL File Hash", (UINT8 *)&msg[cpyofs], ATP_IDENT_KEY_STG);
        SBC_RET_VALIDATE_ERRCODEMSG((ret == SBCOK), SBCNULLP, "Raw Partition SSBL File HASH Fail");
        cpyofs += ATP_IDENT_KEY_STG;


        //ret = SBC_ReadFile(f_hndl[0], EFI_BOOT_FSBL_PATH, &lv);
        SBC_EFI_FSBL_Load(&fsbl_lv);
        SBC_RET_VALIDATE_ERRCODEMSG((ret == SBCOK), SBCNULLP, "FSBL File Reaed Fail");

        //ret = SBC_HashCompute(NULL, lv.value, lv.length, temp_hash);
        ret = SBC_HashCompute(NULL, fsbl_lv.value, fsbl_lv.length, temp_hash);
        SBC_RET_VALIDATE_ERRCODEMSG((ret == SBCOK), SBCNULLP, "FSBL File HASH Fail");

        SBC_mem_print_bin(" FSBL File Hash", (UINT8 *)temp_hash, ATP_IDENT_KEY_STG);
        CopyMem((void *)&msg[cpyofs], temp_hash, ATP_IDENT_KEY_STG);
        cpyofs += ATP_IDENT_KEY_STG;

        if (fbuf != NULL) {
            //lv.value = NULL;
            FreePool(fbuf);
        }

        //
        // Read the SSBL flie
        //
        fbuf = AllocateZeroPool(len_ssbl);
        lv.value = fbuf;
        lv.length = len_ssbl;

        //ret = SBC_ReadFile(f_hndl[0], EFI_BOOT_SSBL_PATH, &lv);
        SBC_EFI_SSBL_Load(NULL, &ssbl_lv);
        SBC_RET_VALIDATE_ERRCODEMSG((ret == SBCOK), SBCNULLP, "SSBL File Reaed Fail");

        ZeroMem((void *)temp_hash, 32);
        //ret = SBC_HashCompute(NULL, lv.value, lv.length, temp_hash);
        ret = SBC_HashCompute(NULL, ssbl_lv.value, ssbl_lv.length, temp_hash);
        SBC_RET_VALIDATE_ERRCODEMSG((ret == SBCOK), SBCNULLP, "SSBL File HASH Fail");
        SBC_mem_print_bin(" SSBL File Hash", (UINT8 *)temp_hash, ATP_IDENT_KEY_STG);
        CopyMem((void *)&msg[cpyofs], temp_hash, ATP_IDENT_KEY_STG);
        cpyofs += ATP_IDENT_KEY_STG;

        if (fbuf != NULL) {
            dprint();
            FreePool(fbuf);
            dprint();
        }
        //dprint();

 
    }

    if (p->bm == BOOT_MODE_RECOVERY) {

        dprint("Migrattion Key Create by Reccovery");
        //ret = SBC_ReadFile(f_hndl[0], EFI_BOOT_FSBL_PATH, &lv);
        SBC_EFI_FSBL_Load(&fsbl_lv);
        SBC_RET_VALIDATE_ERRCODEMSG((ret == SBCOK), SBCNULLP, "FSBL File Reaed Fail");


        //ret = SBC_HashCompute(NULL, lv.value, lv.length, temp_hash);
        ret = SBC_HashCompute(NULL, fsbl_lv.value, fsbl_lv.length, temp_hash);
        SBC_RET_VALIDATE_ERRCODEMSG((ret == SBCOK), SBCNULLP, "FSBL File HASH Fail");

        SBC_mem_print_bin(" FSBL File Hash", (UINT8 *)temp_hash, ATP_IDENT_KEY_STG);
        CopyMem((void *)&msg[cpyofs], temp_hash, ATP_IDENT_KEY_STG);
        cpyofs += ATP_IDENT_KEY_STG;

        if (fbuf != NULL) {
            //lv.value = NULL;
            FreePool(fbuf);
        }

        //
        // Read the SSBL flie
        //
        fbuf = AllocateZeroPool(len_ssbl);
        lv.value = fbuf;
        lv.length = len_ssbl;

        //ret = SBC_ReadFile(f_hndl[0], EFI_BOOT_SSBL_PATH, &lv);
        SBC_EFI_SSBL_Load(NULL, &ssbl_lv);
        SBC_RET_VALIDATE_ERRCODEMSG((ret == SBCOK), SBCNULLP, "SSBL File Reaed Fail");

        ZeroMem((void *)temp_hash, 32);
        //ret = SBC_HashCompute(NULL, lv.value, lv.length, temp_hash);
        ret = SBC_HashCompute(NULL, ssbl_lv.value, ssbl_lv.length, temp_hash);
        SBC_RET_VALIDATE_ERRCODEMSG((ret == SBCOK), SBCNULLP, "SSBL File HASH Fail");
        SBC_mem_print_bin(" SSBL File Hash", (UINT8 *)temp_hash, ATP_IDENT_KEY_STG);
        CopyMem((void *)&msg[cpyofs], temp_hash, ATP_IDENT_KEY_STG);
        cpyofs += ATP_IDENT_KEY_STG;

        if (fbuf != NULL) {
            dprint();
            FreePool(fbuf);
            dprint();
        }
        //dprint();

        //
        // Un-used FSBL  ( into the Raw-partiiont) - Currenrtly 
        //
        ret = SBC_HashCompute(NULL, fwinf->mbr.fsblimg, fwinf->mbr.fsbln, (void *)&msg[cpyofs]);
        SBC_mem_print_bin(" FSBL File Hash", (UINT8 *)&msg[cpyofs], ATP_IDENT_KEY_STG);
        SBC_RET_VALIDATE_ERRCODEMSG((ret == SBCOK), SBCNULLP, "Raw Partition FSBL HASH Fail");
        cpyofs += ATP_IDENT_KEY_STG;

        ret = SBC_HashCompute(NULL, fwinf->mbr.ssblimg, fwinf->mbr.ssbln, (void *)&msg[cpyofs]);
        SBC_mem_print_bin(" SSBL File Hash", (UINT8 *)&msg[cpyofs], ATP_IDENT_KEY_STG);
        SBC_RET_VALIDATE_ERRCODEMSG((ret == SBCOK), SBCNULLP, "Raw Partition SSBL File HASH Fail");
        cpyofs += ATP_IDENT_KEY_STG;

    }




    //
    // Final message digest 
    // 
    ret = SBC_HashCompute(NULL, (UINT8 *)&msg[0], cpyofs, outmsg);
    SBC_RET_VALIDATE_ERRCODEMSG((ret == SBCOK), SBCNULLP, "Raw Partition SSBL File HASH Fail");
errdone:

    if (fwinf != NULL) {
        FreePool(fwinf);
    }

    if (msg != NULL) {
        FreePool(msg);
    }


    return ret;
}


#if 0
SBCStatus  SBC_GenMigrationKey(VOID *priv, UINT32 currbankid, UINT32 prevbankid, VOID *out)
{
  //Migration Key = H(H(Unique HW ID)||H(Current FSBL)||H(Current SSBL)||H(Current KERNEL)||H(Newer SSBL)||H(Newer KERNEL))
    SBCStatus ret = SBCOK;
    UINTN integcnt = 0;
    UINTN migkeycnt = 0;
//  mig_key_t *key = NULL;

    UINT8 *migkey_hash = NULL;

    hw_uniqueinfo_t info;
    UINT8 *integbuf = NULL; // Integration bufefr
    UINTN startaddr = 0;
    UINTN startlba = 0;
    UINTN imglen = 0;
    boot_fw_inf_t *fwinf;

    dprint("Migration Key creation startnig !!!");

    SBC_RET_VALIDATE_ERRCODEMSG((priv != NULL), SBCNULLP, "Invalid Parameter");

    ZeroMem((void *)&info, sizeof info);

    // Step 1. Compute the HW ID 
    _baseboard_sn(&info);
    _memorydevice_sn(&info);
    _nvme_get_serial(&info);

    fwinf = AllocatePool(sizeof(boot_fw_inf_t));
    SBC_RET_VALIDATE_ERRCODEMSG((fwinf != NULL),SBCNULLP, "Firmware Info Memory allocate Nill");

    integbuf = AllocatePool(info.mbsnl + info.mmsnl + info.nvmesnl);
    SBC_RET_VALIDATE_ERRCODEMSG((integbuf != NULL),SBCNULLP, "HW Info Compute buffer Nill");

    integcnt = 0;
    CopyMem((void *)&integbuf[0], info.mbsn, info.mbsnl);
    integcnt = info.mbsnl;

    //Print(L"Next cnt : %d \n", cnt);
    CopyMem((void *)&integbuf[integcnt], info.mmsn, info.mmsnl);
    integcnt += info.mmsnl;

    //Print(L"Next Next cnt : %d \n", cnt);
    CopyMem((void *)&integbuf[integcnt], info.nvmesn, info.nvmesnl);
    integcnt += info.nvmesnl;

    migkey_hash = AllocatePool(SBC_AT_HASH_LEN * 6);
    SBC_RET_VALIDATE_ERRCODEMSG((migkey_hash != NULL),SBCNULLP, "MigKEy Compute buffer Nill");
    migkeycnt = 0;

    ret = SBC_HashCompute(
                             NULL, /* Not yet used */
                             integbuf,
                             integcnt,
                             &migkey_hash[migkeycnt]
                          ) ;

    if (ret != SBCOK) {
      eprint("Device Dice Message Hash compute fail \n");
      goto errdone;
    }

    migkeycnt +=  SBC_AT_HASH_LEN;

    //Step 2. Read Current Image and Hash compute
    startaddr = (BOOT_SECTOR1_OFS | (BOOT_FW_IMGMAX *  (currbankid - 1)));
    startlba = (startaddr >> SBC_RAWPRT_DFLT_SHIFT);
    imglen = ALIGN_VALUE(sizeof *fwinf, SBC_RAWPRT_DFLT_BLK_SZ);

    
    ret = SBC_RawPrtReadBlock(priv, (void *)fwinf->value, (UINT32 *)&imglen, startlba);
    SBC_RET_VALIDATE_ERRCODEMSG((ret == SBCOK), ret, "Raw Partition read fail");

    // Hash compute
    
    ret = SBC_HashCompute(NULL, fwinf->mbr.fsblimg, fwinf->mbr.fsbln, &migkey_hash[migkeycnt]);
    SBC_RET_VALIDATE_ERRCODEMSG((ret == SBCOK), ret, "Hash Compue fail");
    migkeycnt +=  SBC_AT_HASH_LEN;

    ret = SBC_HashCompute(NULL, fwinf->mbr.ssblimg, fwinf->mbr.ssbln,  &migkey_hash[migkeycnt]);
    SBC_RET_VALIDATE_ERRCODEMSG((ret == SBCOK), ret, "Hash Compue fail");
    migkeycnt +=  SBC_AT_HASH_LEN;

    ret = SBC_HashCompute(NULL, fwinf->mbr.osimg, fwinf->mbr.osln,  &migkey_hash[migkeycnt]);
    SBC_RET_VALIDATE_ERRCODEMSG((ret == SBCOK), ret, "Hash Compue fail");
    migkeycnt +=  SBC_AT_HASH_LEN;

    // Step 3. Read the New Image and hash compute

    ZeroMem(fwinf->value, sizeof fwinf);
    startaddr = (BOOT_SECTOR1_OFS | (BOOT_FW_IMGMAX *  (prevbankid - 1)));
    startlba = (startaddr >> SBC_RAWPRT_DFLT_SHIFT);
    imglen = ALIGN_VALUE(sizeof fwinf, SBC_RAWPRT_DFLT_BLK_SZ);

    ret = SBC_RawPrtReadBlock(priv, (void *)fwinf->value, (UINT32 *)&imglen, startlba);
    SBC_RET_VALIDATE_ERRCODEMSG((ret == SBCOK), ret, "Raw Partition read fail");

    ret = SBC_HashCompute(NULL, fwinf->mbr.ssblimg, fwinf->mbr.ssbln,  &migkey_hash[migkeycnt]);
    SBC_RET_VALIDATE_ERRCODEMSG((ret == SBCOK), ret, "Hash Compue fail");
    migkeycnt +=  SBC_AT_HASH_LEN;

    ret = SBC_HashCompute(NULL, fwinf->mbr.osimg, fwinf->mbr.osln,  &migkey_hash[migkeycnt]);
    SBC_RET_VALIDATE_ERRCODEMSG((ret == SBCOK), ret, "Hash Compue fail");
    migkeycnt +=  SBC_AT_HASH_LEN;


    ret = SBC_HashCompute(NULL, migkey_hash, migkeycnt,  (UINT8 *)out);
    SBC_RET_VALIDATE_ERRCODEMSG((ret == SBCOK), ret, "Hash Compue fail");

    
    

errdone:
    if (integbuf != NULL) {
        FreePool(integbuf);
    }

    if (migkey_hash != NULL) {
        FreePool(migkey_hash);
    }

    if (fwinf != NULL) {
      FreePool(fwinf);
    }

    return ret;

}
#endif
// FSBL Integrity check 
SBCStatus  SBC_FSBLIntgCheck([[gnu::unused]]EFI_HANDLE *h_image , 
                             VOID *blkio, VOID *cert, UINTN certlen, 
                             UINTN nrombank, UINTN mode)
{
    SBCStatus ret = SBCOK;

    UINTN   startlba = 0;
    UINT32  imglen = SBC_RAWPRT_DFLT_BLK_SZ;
    [[maybe_unused]] UINT8   imghdr[SBC_RAWPRT_DFLT_BLK_SZ] = { 0, };
    UINT8 *imgbuf = NULL;
//  VOID *blkio;
    UINT8 *cabuf =  NULL;
    UINTN calen = 0;
    //UINTN certlen = 0;
    SBC_AESGcmCtx  ctx;
    SBC_AESContext  aesctx;
    UINT8 decbuf[1024] ={0,};
    UINT8 secret_key[SBC_AT_HASH_LEN] = {0, };

    UINT8 *iv;
    UINT8 *tag;


    switch (mode) {
    case BOOT_MODE_NORMAL:
    case BOOT_MODE_UPDATE:
    case BOOT_MODE_RECOVERY:
      startlba = (SYS_CONF_START_OFS >> SBC_RAWPRT_DFLT_SHIFT);
      imglen = ALIGN_VALUE(SYS_SETTING_STORAGE_LEN, ((EFI_BLOCK_IO_PROTOCOL *)blkio)->Media->BlockSize);
      break;
    case BOOT_MODE_FACTORY:
      startlba = (SYS_CONF_START_OFS >> SBC_RAWPRT_DFLT_SHIFT);
      imglen = ALIGN_VALUE(SYS_SETTING_STORAGE_LEN, ((EFI_BLOCK_IO_PROTOCOL *)blkio)->Media->BlockSize);
      break;
    default:
      eprint("Invalid argument ");
      ret = SBCINVPARAM;
      goto errdone;
      break;
    }

    imgbuf = AllocateZeroPool(imglen);
    SBC_RET_VALIDATE_ERRCODEMSG((imgbuf != NULL), SBCNULLP, "RooTCA load buf allocate fail");


    ret = SBC_RawPrtReadBlock(blkio, 
                              (void *)imgbuf, 
                              &imglen, 
                              startlba);
    SBC_RET_VALIDATE_ERRCODEMSG((ret == SBCOK), ret, "RooTCA load fail");
#ifndef _UNIT_TEST_ON_
    // Pointing the RooTCA Address
    CopyMem((void *)&calen, (void *)&imgbuf[SYS_CONF_ROOT_CA_OFS], LEN_DFLT_OFS);
    cabuf = &imgbuf[SYS_CONF_ROOT_CA_OFS + LEN_DFLT_OFS];

    iv = &imgbuf[SYS_CONF_ROOT_CA_OFS + LEN_DFLT_OFS + calen];
    tag = &imgbuf[SYS_CONF_ROOT_CA_OFS + LEN_DFLT_OFS + calen +  SBC_AT_IV_LEN];

    ret = SBC_DeviceSecuirtyKeyCreate(secret_key);
    SBC_RET_VALIDATE_ERRCODEMSG((ret == SBCOK), 
                                SBCINVPARAM, 
                                "SBC_DeviceSecuirtyKeyCreate fail");
   //offset = 0;
    ctx.out.value = (void *)decbuf;
    //declen = calen;
    ctx.out.length = calen;

    ctx.msg.value = cabuf;
    ctx.msg.length = calen;
    
    aesctx.gcm = &ctx;
    aesctx.algoid = SBC_CIPHER_AES_GCM;

    SBC_AESGcmSetContext((void *)aesctx.gcm,
                         (void *)secret_key,
                         (void *)iv,
                         (void *)tag);


    ret = SBC_AESGcmDecrypt(&aesctx);
    if (ret != SBCOK) {
        SBC_BuildHexFormattedMessage(
            (CONST VOID *)secret_key,
            32,
            L"SFR-Vendor-SP RooTCA decrypt fail (%s) \n",
            mrgmsg, sizeof mrgmsg);

        sbc_err_sysprn(SBC_LOG_CMN_PRIO_ERR, 2,
                     SYS_LOG_HOST_BOOT,
                     SYS_LOG_APP_NAME,
                     SYS_LOG_CSC_NAME,
                     0,
                     SYS_LOG_EVT_DETECTION,
                     mrgmsg);
        goto errdone;
    }

    //SBC_mem_print_bin("RootCA", decbuf, calen);

    //SBC_mem_print_bin("RootCA", cert, certlen);
#else
    calen = rootca_certi_lv.length;
    cabuf = (UINT8 *)rootca_certi_lv.value;

    //SBC_mem_print_bin("Root CA", cabuf, calen);
    //SBC_mem_print_bin("Cert", cert, certlen);
#endif

    ret = SBC_X509VerifyCert(
                      (CONST UINT8 *)cert,  //  Cert
                      certlen,
                      decbuf, // CA
                      calen
        );

    if (ret != SBCOK) {
      int_eprint("RootCA Signature Verify fail \n");
//      SBC_BuildHexFormattedMessage(
//          (CONST VOID *)secret_key,
//          32,
//          L"SFR-Vendor-SP RooTCA decrypt fail (%s) \n",
//          mrgmsg, sizeof mrgmsg);

        sbc_err_sysprn(SBC_LOG_CMN_PRIO_ERR, 2,
                     SYS_LOG_HOST_BOOT,
                     SYS_LOG_APP_NAME,
                     SYS_LOG_CSC_NAME,
                     0,
                     SYS_LOG_EVT_DETECTION,
                     L"SFR-Vendor-SP RootCA Verify Fail \n");
      goto errdone;
    }



    sbc_err_sysprn(SBC_LOG_CMN_PRIO_INFO, 2,
             SYS_LOG_HOST_BOOT,
             SYS_LOG_APP_NAME,
             SYS_LOG_CSC_NAME,
             0,
             L"Validation",
             L"SFR-Vendor-SP RootCA Verify Success \n");


    

errdone:
    if (imgbuf != NULL) {
        FreePool(imgbuf);
        imgbuf=  NULL;
    }
    return ret;

}



//SBCStatus SBC_GenDeviceID(UINT8 *devid)
//{
//    SBCStatus ret = SBCOK;
//    at_key_t key;
//    LV_t    rdlv = {
//        .value = NULL,
//        .length = 0
//    };
//
//#ifndef  SBC_BASEANSWER_TEST
//    hw_uniqueinfo_t info;
//
//#else
//   hw_uniqueinfo_t info = {
//       .mbsn = { 0x51, 0x43, 0x51, 0x34, 0x53, 0x31, 0x32, 0x34, 0x34, 0x34, 0x30, 0x30, 0x4b, 0x52},
//       .mbsnl = 14,
//       .mmsn = {0x30, 0x30, 0x30, 0x30, 0x30, 0x30, 0x30, 0x30},
//       .mmsnl = 8,
//       .nvmesn = {0x36, 0x34, 0x37, 0x39, 0x5f, 0x41, 0x37, 0x39, 0x36, 0x5f, 0x34, 0x41,0x33, 0x30, 0x5f, 0x35, 0x43, 0x37, 0x36 },
//       .nvmesnl = 20
//   };
//
//    CHAR8 *pemkey_priv;
//    CHAR8 *pemkey_pub;
//    UINTN pemsize;
//    CONST CHAR8 *pemheader_priv="-----BEGIN PRIVATE KEY-----";
//    CONST CHAR8 *pemoffter_priv="-----END PRIVATE KEY-----";
//    CONST CHAR8 *pemheader_pub="-----BEGIN PUBLIC KEY-----";
//    CONST CHAR8 *pemoffter_pub="-----END PUBLIC KEY-----";
//   UINT8 *computebuf = NULL;
//   UINTN cnt = 0;
//#endif
//    SBC_RET_VALIDATE_ERRCODEMSG((devid != NULL),SBCNULLP, "Out buffer Nill");
//
//
//
//#ifndef  SBC_BASEANSWER_TEST
//    // TODO : read the device information
//    ZeroMem((void *)&info, sizeof info);
//#else
//
//    _baseboard_sn(&info);
//    SBC_external_mem_print_bin("BaseBoard SN", info.mbsn,info.mbsnl);
//    SBC_mem_print_bin("BaseBoard SN", info.mbsn,info.mbsnl);
//
//    _memorydevice_sn(&info);
//    SBC_external_mem_print_bin("MemoryDevice SN", info.mmsn, info.mmsnl);
//    SBC_mem_print_bin("MemoryDevice SN", info.mmsn, info.mmsnl);
//
//    _nvme_get_serial(&info);
//    SBC_external_mem_print_bin("NVME SN", info.nvmesn,info.nvmesnl);
//    SBC_mem_print_bin("NVME SN", info.nvmesn,info.nvmesnl);
//
//    //_read_fsbl_image(&rdlv);
//    SBC_EFI_FSBL_Load(&rdlv);
//    SBC_RET_VALIDATE_ERRCODEMSG((rdlv.value != NULL), SBCNULLP, "FSBL read fail");
//
//    computebuf = AllocatePool(info.mbsnl + info.mmsnl + info.nvmesnl + rdlv.length);
//    SBC_RET_VALIDATE_ERRCODEMSG((computebuf != NULL),SBCNULLP, "Compute buffer Nill");
//
//    cnt = 0;
//    //Print(L" cnt : %d \n", cnt);
//    CopyMem((void *)&computebuf[0], info.mbsn, info.mbsnl);
//    cnt = info.mbsnl;
//
//    //Print(L"Next cnt : %d \n", cnt);
//    CopyMem((void *)&computebuf[cnt], info.mmsn, info.mmsnl);
//    cnt += info.mmsnl;
//
//    //Print(L"Next Next cnt : %d \n", cnt);
//    CopyMem((void *)&computebuf[cnt], info.nvmesn, info.nvmesnl);
//    cnt += info.nvmesnl;
//
//        //Print(L"Next Next cnt : %d \n", cnt);
//    CopyMem((void *)&computebuf[cnt], rdlv.value, rdlv.length);
//    cnt += rdlv.length;
//
//    dprint("DICE message length  : %d", cnt);
//   dprint("DICE message length  : %d \n", cnt);
//    //SBC_mem_print_bin("Device ID Raw Fmt", computebuf, cnt);
//    ret = SBC_HashCompute(
//                             NULL, /* Not yet used */
//                             computebuf,
//                             cnt,
//                             devid
//                          ) ;
//
//
//
//    SBC_mem_print_bin("Device ID", devid, 32);
//
//#endif
//
//
//    SBC_RET_VALIDATE_ERRCODEMSG((ret == SBCOK), ret, "Hash compute fail");
//
//    SBC_DICESeedKeyPair(devid, &key);
//
//    SBC_external_mem_print_bin("Devid Private", key.d, key.dl);
//    SBC_external_mem_print_bin("Pub", key.q.value, key.ql);
//
//    SBC_ConvertRawKeyPem(
//                    key.d, key.dl,
//                    pemheader_priv, pemoffter_priv,
//                    &pemkey_priv,&pemsize
//            );
//    SBC_external_mem_print_bin("PRIV pem", (UINT8 *)pemkey_priv, (UINT32)pemsize);
//
//    SBC_ConvertRawKeyPem(
//                    key.q.value, key.ql,
//                    pemheader_pub, pemoffter_pub,
//                    &pemkey_pub,&pemsize
//            );
//    SBC_external_mem_print_bin("PUBLIC pem", (UINT8 *)pemkey_pub, (UINT32)pemsize);
//
//
//errdone:
//
//    if(computebuf) {
//        FreePool(computebuf);
//    }
//    return ret;
//
//}
