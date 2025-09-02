#include <Library/BaseLib.h>
//#include <Library/CtLibSuppot.h>
#include <Library/BaseCryptLib.h>
#include <Library/BaseMemoryLib.h>
#include <malloc.h>
#include <Register/Intel/Cpuid.h>

#include <Library/ShellLib.h>
#include <Library/MemoryAllocationLib.h>
#include <Protocol/Smbios.h>

#include <Library/DevicePathLib.h>
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

#include <Library/UefiBootManagerLib.h>

#include <Library/UefiLib/UefiLibInternal.h>
#include <Library/PcdLib.h>

#include <openssl/objects.h>
#include <openssl/bn.h>
#include <openssl/ec.h>
#include <stdarg.h>

#include "SBC_Log.h"
#include "SBC_ErrorType.h"
#include "SBC_CryptAES.h"
#include "SBC_FileCtrl.h"
#include "SBC_TypeDefs.h"
#include "SBC_EccSignVerify.h"
#include "SBC_Config.h"
#include "SBC_AntiTampering.h"
#include "SBC_Util.h"

#include "SBC_UnitTest.h"
#include "SBC_SystemControl.h"

#ifdef _UNIT_TEST_ON_
at_key_t devkey;
at_key_t fwkey;
at_key_t oskey;

extern SBCStatus  SBC_DiceKeysGen(EFI_HANDLE ImageHandle, VOID *p,UINTN normbank, UINTN bm);

void D_SAT_PWT_SFR_001(void *priv)
{
    SBCStatus ret = SBCOK;
    unit_proc_t *p = (unit_proc_t *)priv;
    atp_ident_t *dicekey = (atp_ident_t *)p->keyinfo;

    ZeroMem((void *)&devkey, sizeof devkey);
    ZeroMem((void *)&fwkey, sizeof fwkey);
    ZeroMem((void *)&oskey, sizeof oskey);

    dprint("* D-SAT-PWT-SFR-001 Unit Test \r\n");


    dprint("\t** Load the Unique Information and Generate the Unique Key \r\n");

    ret = SBC_DiceKeysGen(p->blkhnd, dicekey, p->curr_sw_bnk, p->bm);
    SBC_RET_VALIDATE_ERRCODEMSG((ret == SBCOK), ret, "SBC_DiceKeysGen Fail");

    dprint("\t *** Generate the Device ID Key-pair \r\n");
    ret = SBC_DICESeedKeyPair(dicekey->devid, &devkey);
    SBC_RET_VALIDATE_ERRCODEMSG((ret == SBCOK), ret, "Device ID Key-pair Create Fail");
    SBC_mem_print_bin("Device Private Key", devkey.d, devkey.dl);
    SBC_mem_print_bin("Device Public Key", devkey.q.value, devkey.ql);

    dprint("\t *** Generate the Firmware ID Key-pair \r\n");
    ret = SBC_DICESeedKeyPair(dicekey->fwid, &fwkey);
    SBC_RET_VALIDATE_ERRCODEMSG((ret == SBCOK), ret, "Device ID Key-pair Create Fail");
    SBC_mem_print_bin("Firmware Private Key", fwkey.d, fwkey.dl);
    SBC_mem_print_bin("Firmware Public Key", fwkey.q.value, fwkey.ql);


    dprint("\t *** Generate the OS ID Key-pair \r\n");
    ret = SBC_DICESeedKeyPair(dicekey->osid, &oskey);
    SBC_RET_VALIDATE_ERRCODEMSG((ret == SBCOK), ret, "Device ID Key-pair Create Fail");
    SBC_mem_print_bin("OS Private Key", oskey.d, oskey.dl);
    SBC_mem_print_bin("OS Public Key", oskey.q.value, oskey.ql);

    return;
errdone:

    eprint("%a Return Code %d", __FUNCTION__, ret);
    return;
    
}


void D_SAT_PWT_SFR_002(void *priv)
{
    SBCStatus       ret = SBCOK;
    EFI_STATUS      retval = EFI_SUCCESS;
    EFI_HANDLE      *hndl = NULL;
    UINT16          *fblpath = STR_FSBL_F_NAME;
    //UINT16          *fblpath = L"\\boot\\vmlinuz-5.14.0-284.11.1.el9_2.x86_64" ;
    UINT8           *infostart = NULL;
    UINT32          last_of_fsbl = 0;
    UINT32          bsinfolen = 0;
    fsbl_bsinfo_t   bsinfo; 
    UINT32          bsptrcnt = 0;
    CHAR8           base_answer[16] = {0,};
    [[maybe_unused]]UINT8           HashValue[256];
    [[maybe_unused]]UINT32          HashSize =0;
    [[maybe_unused]]UINT32          fsbl_len =0;
    [[maybe_unused]]VOID            *EcPubKey = NULL;
    [[maybe_unused]]UINTN           HandleCount;

    LV_t            rdlv = {
            .length = 0,
            .value = NULL
      };

    unit_proc_t *p = (unit_proc_t *)priv;
    atp_ident_t *dicekey = (atp_ident_t *)p->keyinfo;


    Print(L"* D-SAT-PWT-SFR-002 Unit Test \r\n");

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

    ret = SBC_FindFileBufHndl(fblpath, &HandleCount, hndl);
    SBC_RET_VALIDATE_ERRCODEMSG((ret == SBCOK), ret, "File not found");

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

//  dprint("----------- FSBL Boot Service Informmtion ------------");
//  dprint("Signature Len     : %d", bsinfo.m.siglen );
//  dprint("Firmware Info Len : %d", bsinfo.m.fwinfolen );
//  dprint("Certificate Len   : %d", bsinfo.m.certlen );
//  dprint("BaseAnswer Len    : %d", bsinfo.m.banswlen );
//  dprint("BSinfo verdion    : %d", bsinfo.m.bsinfv );
//  dprint("Spec.1 Value      : %d", bsinfo.m.reserv1 );
//  dprint("Spec.2 Value      : %d", bsinfo.m.reserv2 );

    bsinfolen = bsinfo.m.siglen + bsinfo.m.fwinfolen + bsinfo.m.certlen  + bsinfo.m.banswlen;

    Print(L"\t** Extract the Base Answer \r\n");
      
    fsbl_len = last_of_fsbl = rdlv.length - FSBL_BNIFO_SIZE - bsinfolen;
    infostart = &((UINT8 *)rdlv.value)[last_of_fsbl];

    //dprint("FSBL Last : %d", last_of_fsbl);
    ////SBC_external_mem_print_bin("Addtional Information", infostart,bsinfolen  );

    fsbl_bsinfo_ptr_t info = {NULL, NULL, NULL, NULL};

    info.baseansw = (VOID *)&infostart[bsptrcnt];
    bsptrcnt += bsinfo.m.banswlen;

    CopyMem(base_answer, info.baseansw, bsinfo.m.banswlen);

    //SBC_external_mem_print_bin("Base Answer", (UINT8 *)info.baseansw,  bsinfo.m.banswlen );

    info.fwinfo = (VOID *)&infostart[bsptrcnt];
    bsptrcnt += bsinfo.m.fwinfolen;

    //SBC_external_mem_print_bin("FW Info", (UINT8 *)info.fwinfo,  bsinfo.m.fwinfolen );

    info.certi = (VOID *)&infostart[bsptrcnt];
    bsptrcnt += bsinfo.m.certlen;

    //SBC_external_mem_print_bin("Certificate", (UINT8 *)info.certi,  bsinfo.m.certlen );

    info.signature = (VOID *)&infostart[bsptrcnt];
    bsptrcnt += bsinfo.m.siglen;   

    Print(L"\t\t*Base Answer : \"%a\" \r\n", base_answer);

    Print(L"\t**Base Answer Encrypt and Store \r\n");

    ret = SBC_BaseAnswerEncryptStore(p->blkhnd, 
                                     (UINT8 *)base_answer, sizeof base_answer, 
                                     dicekey->osid,
                                     SYS_OSID_KEY_LEN);

    Print(L"\t**(Expected Results) Base Answer Validate \r\n");
    ret = SBC_BaseAnswerValidate(p->blkhnd,
                                 (UINT8 *)base_answer, sizeof base_answer,
                                 dicekey->osid,
                                 SYS_OSID_KEY_LEN);
    


    return;
errdone:

    if (rdlv.value) {
        FreePool(rdlv.value);
        rdlv.value = NULL;
    }
    eprint("%a Return Code %d", __FUNCTION__, ret);
    return;
}

static SBCStatus _unit_test_baseanswer_extract_from_disk(VOID *blkio, base_ansid_t *p)
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
    Print(L"SBC_RawPrtReadBlock fail (%p)\n", blkio);
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

  CopyMem((void *)p->iv, (void *)&loadbuf[offset], BASE_ANS_IV_KEY_STR);
  offset += BASE_ANS_IV_KEY_STR;


  CopyMem((void *)p->tag, (void *)&loadbuf[offset], BASE_ANS_TAG_LEN);
  offset += BASE_ANS_TAG_LEN;

#ifdef _UNIT_TEST_ON_
//dprint("Enc Msg Len : %d", p->msglen);
  Print(L"\t\t***Base Answer Read from Raw-partition \r\n");
  SBC_mem_print_bin("Base Answer Encrypt Message", p->encmsg, p->msglen);
//SBC_mem_print_bin("Enc IV", p->iv, BASE_ANS_IV_KEY_STR);
//SBC_mem_print_bin("Tag Message", p->tag, BASE_ANS_TAG_LEN);
#endif  

errdone:
  return ret;
}

void D_SAT_PWT_SFR_003(void *priv)
{
    SBCStatus       ret = SBCOK;
    fsbl_bsinfo_t   bsinfo;
    fsbl_bsinfo_ptr_t blobinfo;
    unit_proc_t *p = (unit_proc_t *)priv;
    atp_ident_t *dicekey = (atp_ident_t *)p->keyinfo;
    base_ansid_t bs_ansid;

    Print(L"* D-SAT-PWT-SFR-003 Unit Test \r\n");
    ret = SBC_ReadFwBootSrvInformation(STR_FSBL_F_NAME, (void *)&blobinfo, (void *)&bsinfo);
    SBC_RET_VALIDATE_ERRCODEMSG((ret == SBCOK), ret, "Boot Service Info Load Fail");

//  dprint("----------- Boot Service Informmtion ------------");
//  dprint("Signature Len     : %d", bsinfo.m.siglen );
//  dprint("Firmware Info Len : %d", bsinfo.m.fwinfolen );
//  dprint("Certificate Len   : %d", bsinfo.m.certlen );
//  dprint("BaseAnswer Len    : %d", bsinfo.m.banswlen );
//  dprint("BSinfo verdion    : %d", bsinfo.m.bsinfv );
//  dprint("Spec.1 Value      : %d", bsinfo.m.reserv1 );
//  dprint("Spec.2 Value      : %d", bsinfo.m.reserv2 );

    Print(L"\t** Encrypted Base-answer and OSID load \r\n");

    _unit_test_baseanswer_extract_from_disk(p->blkhnd, &bs_ansid);

    Print(L"\t\t*** Encrypt Base Answer Extract \r\n");
    SBC_mem_print_bin("Encrypted Base Answer", (UINT8 *)bs_ansid.encmsg, bsinfo.m.banswlen);

    Print(L"\t\t*** OSID Key Load \r\n");
    SBC_mem_print_bin("OSID", (UINT8 *)dicekey->osid, 32);

   
    Print(L"\t** Base Answer Validation \r\n");
    ret = SBC_BaseAnswerValidate(p->blkhnd, 
                                 blobinfo.baseansw, bsinfo.m.banswlen, 
                                 dicekey->osid, 32);

    
    return;
errdone:

    return;
}

void D_SAT_PWT_SFR_003_Tampre(void *priv)
{
    SBCStatus       ret = SBCOK;
    fsbl_bsinfo_t   bsinfo;
    fsbl_bsinfo_ptr_t blobinfo;
    unit_proc_t *p = (unit_proc_t *)priv;
    atp_ident_t *dicekey = (atp_ident_t *)p->keyinfo;
    base_ansid_t bs_ansid;

    Print(L"* D-SAT-PWT-SFR-003 Tamper Unit Test \r\n");
    ret = SBC_ReadFwBootSrvInformation(L"\\EFI\\BOOT\\FSBL.efi.tamper", (void *)&blobinfo, (void *)&bsinfo);
    SBC_RET_VALIDATE_ERRCODEMSG((ret == SBCOK), ret, "Boot Service Info Load Fail");

//  dprint("----------- Boot Service Informmtion ------------");
//  dprint("Signature Len     : %d", bsinfo.m.siglen );
//  dprint("Firmware Info Len : %d", bsinfo.m.fwinfolen );
//  dprint("Certificate Len   : %d", bsinfo.m.certlen );
//  dprint("BaseAnswer Len    : %d", bsinfo.m.banswlen );
//  dprint("BSinfo verdion    : %d", bsinfo.m.bsinfv );
//  dprint("Spec.1 Value      : %d", bsinfo.m.reserv1 );
//  dprint("Spec.2 Value      : %d", bsinfo.m.reserv2 );

    Print(L"\t** Encrypted Base-answer and OSID load \r\n");

    _unit_test_baseanswer_extract_from_disk(p->blkhnd, &bs_ansid);

    Print(L"\t\t*** Encrypt Base Answer Extract \r\n");
    SBC_mem_print_bin("Encrypted Base Answer", (UINT8 *)bs_ansid.encmsg, bsinfo.m.banswlen);

    Print(L"\t\t*** OSID Key Load \r\n");
    SBC_mem_print_bin("OSID", (UINT8 *)dicekey->osid, 32);

   
    Print(L"\t** Base Answer Validation \r\n");
    ret = SBC_BaseAnswerValidate(p->blkhnd, 
                                 blobinfo.baseansw, bsinfo.m.banswlen, 
                                 dicekey->osid, 32);

    if (ret != SBCOK) {
        goto errdone;
    }

    return;
errdone:

    SBC_ShutdownSystem();
    return;
}

void D_SAT_PWT_SFR_006_FSBL(void *priv)
{
    SBCStatus       ret = SBCOK;
    [[maybe_unused]] fsbl_bsinfo_t   bsinfo;
    [[maybe_unused]] fsbl_bsinfo_ptr_t blobinfo;
    unit_proc_t *p = (unit_proc_t *)priv;
    [[maybe_unused]] atp_ident_t *dicekey = (atp_ident_t *)p->keyinfo;
    [[maybe_unused]] base_ansid_t bs_ansid;
    LV_t baseansr;


    Print(L"* D-SAT-PWT-SFR-006 FSBL&SSBL Tamper Unit Test \r\n");

    Print(L"\t** FSBL Normal Boot ( Verify the FSBL signature ) \r\n");
    ret = SBC_FSBL_Verify(p->blkhnd, &baseansr,  p->curr_sw_bnk, p->bm, STR_FSBL_F_NAME);
    if (ret != SBCOK) {
        goto errdone;
    }


    //L"\\EFI\\BOOT\\SSBL.efi.bin"
    Print(L"\t** SSBL Normal Boot ( Verify the SSBL signature ) \r\n");
    ret = SBC_SSBL_Verify(p->blkhnd, &baseansr,  p->curr_sw_bnk, p->bm, L"\\EFI\\BOOT\\SSBL.efi.bin");
    if (ret != SBCOK) {
        goto errdone;
    }

    extern SBCStatus SBC_GRUB_LoadAndStart(EFI_HANDLE ImageHandle);
    SBC_GRUB_LoadAndStart(NULL);
    while (1) {
    }
    return;

errdone:

    SBC_ShutdownSystem();
    return;
}


void D_SAT_PWT_SFR_006_TamperFSBL(void *priv)
{
    SBCStatus       ret = SBCOK;
    [[maybe_unused]] fsbl_bsinfo_t   bsinfo;
    [[maybe_unused]] fsbl_bsinfo_ptr_t blobinfo;
    unit_proc_t *p = (unit_proc_t *)priv;
    [[maybe_unused]] atp_ident_t *dicekey = (atp_ident_t *)p->keyinfo;
    [[maybe_unused]] base_ansid_t bs_ansid;
    LV_t baseansr;


    Print(L"* D-SAT-PWT-SFR-006 FSBL&SSBL Tamper Unit Test \r\n");

    Print(L"\t** FSBL Normal Boot ( Verify the FSBL signature ) \r\n");
    ret = SBC_FSBL_Verify(p->blkhnd, &baseansr,  p->curr_sw_bnk, p->bm, STR_FSBL_F_NAME);
    if (ret != SBCOK) {
        goto errdone;
    }


    //L"\\EFI\\BOOT\\SSBL.efi.bin"
    Print(L"\t** SSBL AbNormal Boot ( Verify the SSBL signature ) \r\n");
    ret = SBC_SSBL_Verify(p->blkhnd, &baseansr,  p->curr_sw_bnk, p->bm, L"\\EFI\\BOOT\\SSBL.efi.tamper");
    if (ret != SBCOK) {
        goto errdone;
    }

//  extern SBCStatus SBC_GRUB_LoadAndStart(EFI_HANDLE ImageHandle);
//  SBC_GRUB_LoadAndStart(NULL);
//  while (1) {
//  }



    return;


errdone:
    SBC_ShutdownSystem();
    return;
}

void SBC_UnitTestSFR001_TO_003(void *priv)
{
    D_SAT_PWT_SFR_001(priv);
    D_SAT_PWT_SFR_002(priv);
    D_SAT_PWT_SFR_003(priv);
    D_SAT_PWT_SFR_003_Tampre(priv);

    return;
}


void SBC_UnitFsblNormalTamperTest(void *priv)
{
    D_SAT_PWT_SFR_006_FSBL(priv);

}

void SBC_UnitFsblAbNormalTamperTest(void *priv)
{
    D_SAT_PWT_SFR_006_TamperFSBL(priv);
}

#endif

