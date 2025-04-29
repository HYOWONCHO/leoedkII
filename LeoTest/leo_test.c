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


#include <string.h>
#include <stdio.h>
#include <stdlib.h>

#include "leo_test.h"

#ifdef UEFI_FILE_OP
#include <Library/UefiBootServicesTableLib.h>
#include <Library/FileHandleLib.h>
#endif

#include "SBC_Log.h"
#include "SBC_ErrorType.h"
#include "SBC_CryptAES.h"
#include "SBC_FileCtrl.h"

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

VOID *Ec1;
VOID *Ec2;
// Length value
typedef struct _lv_t {
  UINTN length;
  UINT8 *value;
}LV_t;




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

EFI_STATUS
SBC_CreateKey(VOID **keyContext, LV_t *privkey, LV_t *pubkey)
{
  //BOOLEAN ret;

  VOID *_keyContext = NULL;

  if(keyContext == NULL) {
    return EFI_INVALID_PARAMETER;
  }
  Print(L"Ecc new by Nid ( Length : %d )\n", pubkey->length);

  // Allocate and initialize one Elliptic Curve Context
  _keyContext = EcNewByNid(CRYPTO_NID_SECP256R1);
  if(_keyContext == NULL) {
    Print(L"Allocate ECC curve context fail \n");
    return EFI_NOT_READY;
  }

  Print(L"KeyContext Objec : 0x%x \n", *keyContext);

  EcGenerateKey(_keyContext,  pubkey->value, &pubkey->length);
  Print(L"Public key: \n");
  //x_mem_print_bin(NULL,pubkey->value, pubkey->length);

  *keyContext = _keyContext;


  return EFI_SUCCESS;
}




#define EC_CURVE_NUM_SUPPORTED  3
UINTN  EcCurveList[EC_CURVE_NUM_SUPPORTED]   = { CRYPTO_NID_SECP256R1, CRYPTO_NID_SECP384R1, CRYPTO_NID_SECP521R1 };
UINTN  EcKeyHalfSize[EC_CURVE_NUM_SUPPORTED] = { 32, 48, 66 };

EFI_STATUS
TestVerifyEcDh (
    VOID
  )
{

  UINTN    CurveCount;

  for (CurveCount = 0; CurveCount < EC_CURVE_NUM_SUPPORTED; CurveCount++) {
    Print(L"Curve %x \n", EcCurveList[CurveCount]);
    Ec1 = EcNewByNid (EcCurveList[CurveCount]);
    if (Ec1 == NULL) {
      Print(L"EC1Allocate ECC curve context fail \n");
      return 0;
    }

    Ec2 = EcNewByNid (EcCurveList[CurveCount]);
    if (Ec2 == NULL) {
      Print(L"EC2 Allocate ECC curve context fail \n");
      return 0;
    }
  }

  return 0;
}

/**
 * @brief Generate the RNG
 *
 * @param[in]   seed      Random seed buffer
 * @param[in]   szseed    Length of seed buffer
 * @param[in]   szrng     Number of Random size
 * @param[out]  rngdata   Random data
 *
 * @return  On success, return the SBCOK, otherwise return approiate value
 */
SBCStatus SBC_RngGeneration(UINT8* seed, UINTN szseed, UINTN szrng, UINT8* rngdata)
{

  BOOLEAN status = TRUE;


  if(seed == NULL || rngdata == NULL) {
    Print(L"%s args point to NULL \n", __FUNCTION__);
    return SBCNULLP;
  }

  if(szseed <= 0 || szrng <= 0) {
    Print(L"%s arg has length os zero \n");
    return SBCZEROL;
  }



  status = RandomSeed(seed, szseed);
  if(status == FALSE) {
    Print(L"RandomSeed fail \n");
    return SBCFAIL;
  }

  status = RandomBytes(rngdata, szrng);
  if(status != TRUE) {
    Print(L"RandomBytes fail \n");
    return SBCFAIL;
  }

  return SBCOK;



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

EFI_STATUS
EFIAPI
UefiMain (
  IN EFI_HANDLE        ImageHandle,
  IN EFI_SYSTEM_TABLE  *SystemTable
  )
{
  BOOLEAN ret = 0;
  //UINT32 rand[32] ={0, };
  UINT8 randout[32] = {0, };
  UINT8 hashout[32] = {0, };

  UINT8 mackey[32] = {0, };
  UINT8 macvalue[32] = {0, };
  UINT8 macmsg[32] = {0, };
  VOID *hmacHandle;



#if 1
  UINT8 symmkey[SBC_KEY_LEN_256] = {0, };
  SBC_AESContext aesctx = {
    .handle = NULL,
    .key = symmkey,
    .keylen = SBC_KEY_STRENGTH_256,
    .algoid = SBC_CIPHER_NONE
  };

#endif
#if 0
  UINT8 pubkeyBuf[66 *2];
  LV_t public = {
    .value = pubkeyBuf,
    .length = sizeof pubkeyBuf,
  };
#endif

#if 1
  //----- AES Test variable start
  //UINT8 aesbuf[] = L"Welcome to the Enjoy world !!!";
  //CHAR8 plaintxt[] = "Welcome";
  UINT8 plaintxt[16] = {0, };
  UINT8 aesbuf[256] = {0, };
  SBC_AESCBCCtx  cbcctx;
  SBC_CipherTLV plainlv = {
    .tag = 0,
    //.length = (UINTN)strlen((unsigned char *)aesbuf),
    .length = sizeof(Aes128CbcData),
    .value = (UINT8 *)Aes128CbcData
  };

  SBC_CipherTLV enclv = {
    .tag = 0,
    .length = 0,
    .value = aesbuf
  };
#endif

#if 0
  SBC_CipherTLV declv = {
    .tag = 0,
    .length = 0,
    .value = aesbuf
  };

#endif

  //----- AES Test variabl end
  //CHAR8 testfile[] ="/home/leoc/src/edk2/eck2_biuld_setup.sh";
  SBCLOGMSG("Leo Test Starting \n");
  //DEBUG((DEBUG_INFO,"Image Handle Ptr : %p \r\n", ImageHandle));


  CpuidSerialNumber();
  ret = RandomBytes(randout, sizeof randout);
  if(ret == FALSE) {
    Print(L"RandomByte fail \n");
    return EFI_LOAD_ERROR;
  }

  ret = RandomBytes(mackey, 32);
  if(ret == FALSE) {
    Print(L"RandomByte fail \n");
    return EFI_LOAD_ERROR;
  }

  ret = RandomBytes(plaintxt, 16);
  if(ret == FALSE) {
    Print(L"Plaintxt Random byte fail \n");
    return EFI_LOAD_ERROR;
  }



  Print(L"Rand Out : \n");
  //x_mem_print_bin(NULL,randout, 32);

  Sha256HashAll((CONST VOID *)randout, 32, hashout);
  Print(L"SHA256 Out : \n");
  //x_mem_print_bin(NULL,hashout, 32);

  //free(FwPrivKey);
  //

  hmacHandle = HmacSha256New();

  SBC_hmac_compute(hmacHandle, mackey, sizeof mackey, macmsg, sizeof macmsg, macvalue);

  Print(L"MAC Out : \n");
  //x_mem_print_bin(NULL,macvalue, 32);

  HmacSha256Free(hmacHandle);

  //DEBUG((DEBUG_INFO , "%s:%d \n",__func__, __LINE__));
#if 1
  aesctx.cbc = &cbcctx;
  aesctx.key = Aes256CbcKey;
  //DEBUG((DEBUG_INFO , "%s:%d \n",__func__, __LINE__));
  aesctx.keylen =SBC_KEY_STRENGTH_256;
  //DEBUG((DEBUG_INFO , "%s:%d \n",__func__, __LINE__));
  aesctx.algoid = SBC_CIPHER_AES_CBC;
  //DEBUG((DEBUG_INFO , "%s:%d \n",__func__, __LINE__));
  aesctx.in = &plainlv;
  //DEBUG((DEBUG_INFO , "%s:%d \n",__func__, __LINE__));
  aesctx.out = &enclv;
  //DEBUG((DEBUG_INFO , "%s:%d \n",__func__, __LINE__));
  aesctx.iv = Aes128CbcIvec;
  //DEBUG((DEBUG_INFO , "%s:%d \n",__func__, __LINE__));
#endif


  
  

  //Print(L"AES Plain text (%d) (%s) \r\n", plainlv.length, (CHAR8 *)plainlv.value);
  //x_mem_print_bin(NULL, plainlv.value, plainlv.length);


  Print(L"AES Init : %d\n", SBC_AESInit(&aesctx));
  Print(L"AES handle : 0x%08x\n", aesctx.handle);
  //DEBUG((DEBUG_INFO , "%s:%d \n",__func__, __LINE__));

  //aesctx.in = &enclv;
  //aesctx.out = &declv;
#if 1
  if(SBC_AESEncrypt(&aesctx) != SBCOK) {
    Print(L"Encrypt Fail \r\n");
  }
  else {
      //DEBUG((DEBUG_INFO , "%s:%d \n",__func__, __LINE__));
    Print(L"Encrypt Buff \r\n");
    SBC_mem_print_bin(NULL, aesctx.out->value, aesctx.out->length);
    DEBUG((DEBUG_INFO , "%s:%d \n",__func__, __LINE__));
  }
#endif


  aesctx.in = &enclv;
  aesctx.out = &plainlv;
  if(SBC_AESDecrypt(&aesctx) != SBCOK) {
    Print(L"Encrypt Fail \r\n");
  }
  else {
      //DEBUG((DEBUG_INFO , "%s:%d \n",__func__, __LINE__));
    Print(L"Decrypt Buff \r\n");
    SBC_mem_print_bin(NULL, aesctx.out->value, aesctx.out->length);
    DEBUG((DEBUG_INFO , "%s:%d \n",__func__, __LINE__));
  }


  SBC_AESDeInit(&aesctx);
  DEBUG((DEBUG_INFO , "%s:%d \n",__func__, __LINE__));

  /// File Test
  EFI_HANDLE HandleBuffer = NULL;
  UINTN HandleCount;
  CHAR16 fname[] = L"LeoTest/leo_test/deps.txt";
  //CHAR8 fdata[] = "welcom test file";
  //SBCStatus fret = SBCOK;

  HandleCount = SBC_GetFileSysHandleBuffer(&HandleBuffer);
    if(HandleCount <= 0) {
    Print(L"Protocol not found (%d) \n", HandleCount);
    return 3;
  }

  SBC_ListDirectory(HandleBuffer);

//  if((fret = SBC_CreateFile(HandleBuffer, fname)) != SBCOK) {
//    DEBUG((DEBUG_ERROR,"%a:%d Fail (%d) \n", fret));
//    //SBCLOGMSG("Fail(%d)\n", fret);
//  }

    //WriteToFile(HandleBuffer);
//  SBC_ListDirectory(HandleBuffer);
//  SBCWriteFile(HandleBuffer, fname, fdata);
    SBC_ReadFlie(HandleBuffer, fname );
 



   return EFI_SUCCESS;
}

