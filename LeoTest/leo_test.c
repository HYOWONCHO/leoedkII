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

  RETURN_STATUS status = RETURN_SUCCESS;

  status = SerialPortInitialize();
  if(status != RETURN_SUCCESS) {
    dprint("SerialPortInitialize fail \n");
    Print(L"SerialPortInitialize fail \n");
  }
  else {
    dprint("SerialPortInitialize done \n");
    Print(L"SerialPortInitialize done \n");
  }

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

  //nvme_get_serial();
//  CHAR8 *base_answer = "anti-tampering!?";
    UINT8 devid[32] = {0,};
////  SBC_BaseAnswerValidate((UINT8 *)base_answer, strlen(base_answer));
//  get_blokio_handleparse();
//  GetDiskSerialNumber();
//  GetSSDSerial();
    SBC_GenDeviceID(devid);
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

