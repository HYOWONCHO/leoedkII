#include <Library/BaseMemoryLib.h>
#include <Library/MemoryAllocationLib.h>
#include <Library/BaseLib.h>
#include <Protocol/Smbios.h> // System Management BIOS header


#include "SBC_CryptAES.h"
#include "SBC_TypeDefs.h"

#include "SBC_Util.h"
#include "SBC_Config.h"
#include "SBC_FileCtrl.h"

#include "SBC_Hashing.h"
#include "SBC_AntiTampering.h"
#include "SBC_EccSignVerify.h"


static SBCStatus _baseanswer_extract_from_disk(LV_t *lv)
{

    EFI_STATUS Status;
    SBCStatus ret = SBCOK;
    EFI_HANDLE f_hndl = NULL;
    CHAR16 *basefile = L"base_answer.txt";
    
    //LV_t bsanswer;
    //UINT8 rdbuf[256];
#ifdef  SBC_BASEANSWER_TEST
    
    //CHAR8 *baseanswer[64] = {0, };
    //const CHAR8 *key = "33ac9eccc4cc75e2711618f80b1548e8";
    //const CHAR8 *iv = "0000000000000000";
    // need to convert from str to hex;
    //UINT8 *answer = "E06B9DBDB345C774B545FFC65333307C732B5C524D384B32DA7E5C8646B26A";  
    //const CHAR8 *answer = "\xE0\x6B\x9D\xBD\xB3\x45\xC7\x74\xB5\x45\xFF\xC6\x53\x33\x30\x7C\x73\x2B\x5C\x52\x4D\x38\x4B\x32\xDA\x7E\x5C\x86\x46\xB2\x6A"; 
#else
    UINT8 *base_answer = NULL;
    UINT8 *key = NULL;
    UINT8 *tag = NULL;
    UINTN basefile_sz  = 0;
#endif

    SBC_RET_VALIDATE_ERRCODEMSG((lv != NULL), SBCNULLP, "LV Nill");
    // check that the protocol is available 
    if(SBC_FileSysFindHndl(&f_hndl) <= 0) {
        ret = SBCFAIL;
        eprint("SBC_FileSysFindHndl fail");
        goto errdone;
    }
 
#ifdef  SBC_BASEANSWER_TEST
    //|------------|-----------|----------|
    //|  enc msg   | tag msg   |   iv     |
    //|------------|-----------|----------|
    //|   ?        |  15B      |   12B    |
//  CopyMem((void *)&((UINT8 *)lv->value)[lv->length], bsanswer.value, bsanswer.length);
//  lv->length += bsanswer.length;
    // Copy IV
    //CopyMem((void *)&lv->value[lv->length], &iv, 12);
    //lv->length += strlen(iv);




    //dprint("%s size : %d", (CHAR8 *)basefile, basefile_sz);




#else
    // TO DO : SHOULD be preparing which the file reading.

    ret = SBC_GetFileSize(basefile, &basefile_sz);
    SBC_RET_VALIDATE_ERRCODEMSG((ret == SBCOK), ret, "File size getting fail");

    lv->value = AllocatePool(basefile_sz);
    SBC_RET_VALIDATE_ERRCODEMSG((lv->value != NULL), SBCNULLP, "Not enough memory");

    ZeroMem(lv->value, basefile_sz);
#endif

    Status = SBC_ReadFile(f_hndl, basefile, lv);
    //dprint("Readfile status : %d", Status);
    //SBC_external_mem_print_bin("Base-answer", (UINT8 *)lv->value, (UINTN)lv->length);
    SBC_RET_VALIDATE_ERRCODEMSG((Status == EFI_SUCCESS),ret, "Disk read fail");
    //dprint("Key extract");

#ifndef  SBC_BASEANSWER_TEST
    // TODO : basefile decrypt 
    // IV 
#endif
errdone:
    return ret;
}

SBCStatus SBC_BaseAnswerEncryptStore(UINT8 *out, UINTN *outl)
{
    SBCStatus ret = SBCOK;
#if 0
#ifdef  SBC_BASEANSWER_TEST
    CHAR8 *base_answer = "anti-tampering!?";
    //CHAR8 *key = "33ac9eccc4cc75e2711618f80b1548e8";
    //CHAR8 *iv = "00000000000000000000000000000000";
    // need to convert from str to hex;
    //UINT8 *answer = "E06B9DBDB345C774B545FFC65333307C732B5C524D384B32DA7E5C8646B26A";  
    //UINT8 *answer = "\xE0\x6B\x9D\xBD\xB3\x45\xC7\x74\xB5\x45\xFF\xC6\x53\x33\x30\x7C\x73\x2B\x5C\x52\x4D\x38\x4B\x32\xDA\x7E\x5C\x86\x46\xB2\x6A"; 

#else    
    UINT8 *base_answer = NULL;
    UINT8 *key = NULL;
    UINT8 *tag = NULL;
#endif

    //UINT8 *tagbase;
    //UINT8 *encbase;
    //UINT8 *ivbase;



    LV_t lv;

    SBC_RET_VALIDATE_ERRCODE((out != NULL), SBCNULLP);
    SBC_RET_VALIDATE_ERRCODE((outl <= 0), SBCZEROL);

    lv.value = out;

    lv.length = *outl;

    ret = _baseanswer_extract_from_disk(&lv);
    SBC_RET_VALIDATE_ERRCODEMSG((ret != SBCOK), SBCIO, "Baseanswer read fail");

   
errdone:
    *outl = lv.length;
#endif
    return ret;

}



SBCStatus  SBC_BaseAnswerValidate(UINT8 *answer, UINTN answerl)
{
    SBCStatus ret = SBCOK;
    UINT8 rdbuf[256];
    UINT8 baseanswer[256] = {0, };
    LV_t lv = {
        .value = baseanswer,
        .length = 0
    };

    SBC_RET_VALIDATE_ERRCODEMSG((answer != NULL), SBCNULLP, "Answer is Nill");

    ZeroMem(&lv, sizeof lv);

    _lv_set_data(&lv, rdbuf, sizeof rdbuf);

   
    ret = _baseanswer_extract_from_disk(&lv);
    SBC_RET_VALIDATE_ERRCODEMSG((ret == SBCOK),ret, "Disk read fail");
#ifdef  SBC_BASEANSWER_TEST

    SBC_external_mem_print_bin("answer", answer, answerl);
    SBC_external_mem_print_bin("Base answer", (UINT8 *)lv.value, lv.length - 2);
    if(strncmp((const char *)lv.value, (const char *)answer, answerl) != 0) {
        eprint("Expected answer and Base-answer is not idential");
        Print(L"Expected answer and Base-answer is not idential \n");
        ret = SBCFAIL;
        goto errdone;
    }
#else
    // TO DO : SHOULD be extract the IV, Base-answer which included the TAG
    // And then, decrypt the encrypted base-answer
#endif



    Print(L"Expected answer and Base-answer is  idential \n");
    dprint("Expected answer and Base-answer is  idential");
    

errdone:
    return ret;

}

SBCStatus SBC_GenDeviceID(UINT8 *devid)
{
    SBCStatus ret = SBCOK;
    at_key_t key;
    
#ifndef  SBC_BASEANSWER_TEST
    hw_uniqueinfo_t info;

#else
   hw_uniqueinfo_t info = {
       .mbsn = { 0x51, 0x43, 0x51, 0x34, 0x53, 0x31, 0x32, 0x34, 0x34, 0x34, 0x30, 0x30, 0x4b, 0x52},
       .mbsnl = 14,
       .mmsn = {0x30, 0x30, 0x30, 0x30, 0x30, 0x30, 0x30, 0x30},
       .mmsnl = 8,
       .hdsn = {0x36, 0x34, 0x37, 0x39, 0x5f, 0x41, 0x37, 0x39, 0x36, 0x5f, 0x34, 0x41,0x33, 0x30, 0x5f, 0x35, 0x43, 0x37, 0x36 },
       .hdsnl = 20
   };

    CHAR8 *pemkey_priv;
    CHAR8 *pemkey_pub;
    UINTN pemsize;
    CONST CHAR8 *pemheader_priv="-----BEGIN PRIVATE KEY-----";
    CONST CHAR8 *pemoffter_priv="-----END PRIVATE KEY-----";
    CONST CHAR8 *pemheader_pub="-----BEGIN PUBLIC KEY-----";
    CONST CHAR8 *pemoffter_pub="-----END PUBLIC KEY-----";
   UINT8 *computebuf = NULL;
   UINTN cnt = 0;
#endif
    SBC_RET_VALIDATE_ERRCODEMSG((devid != NULL),SBCNULLP, "Out buffer Nill");

   

#ifndef  SBC_BASEANSWER_TEST
    // TODO : read the device information 
    ZeroMem((void *)&info, sizeof info);
#else
    computebuf = AllocatePool(info.mbsnl + info.mmsnl + info.hdsnl);
    SBC_RET_VALIDATE_ERRCODEMSG((computebuf != NULL),SBCNULLP, "Compute buffer Nill");

    CopyMem((void *)&computebuf[0], info.mbsn, info.mbsnl);
    cnt = info.mbsnl;

    CopyMem((void *)&computebuf[cnt], info.mmsn, info.mmsnl);
    cnt += info.mmsnl;

    CopyMem((void *)&computebuf[cnt], info.hdsn, info.hdsnl);
    cnt += info.mbsnl;

    ret = SBC_HashCompute(
                             NULL, /* Not yet used */
                             computebuf,
                             cnt,
                             devid
                          ) ;




#endif


    SBC_RET_VALIDATE_ERRCODEMSG((ret == SBCOK), ret, "Hash compute fail");

    SBC_DICESeedKeyPair(devid, &key);

    SBC_external_mem_print_bin("Devid Private", key.d, key.dl);
    SBC_external_mem_print_bin("Pub", key.q.value, key.ql);

    SBC_ConvertRawKeyPem(
                    key.d, key.dl,
                    pemheader_priv, pemoffter_priv,
                    &pemkey_priv,&pemsize
            );
    SBC_external_mem_print_bin("PRIV pem", (UINT8 *)pemkey_priv, (UINT32)pemsize);

    SBC_ConvertRawKeyPem(
                    key.q.value, key.ql,
                    pemheader_pub, pemoffter_pub,
                    &pemkey_pub,&pemsize
            );
    SBC_external_mem_print_bin("PUBLIC pem", (UINT8 *)pemkey_pub, (UINT32)pemsize);
errdone:

    if(computebuf) {
        FreePool(computebuf);
    }
    return ret;

}

