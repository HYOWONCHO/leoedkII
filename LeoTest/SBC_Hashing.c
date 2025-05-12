
#include <Library/BaseLib.h>
#include <Library/BaseCryptLib.h>
#include <Library/PrintLib.h>

#include "SBC_Util.h"
#include "SBC_ErrorType.h"
#include "SBC_Hashing.h"

#include "SBC_Config.h"

#include <string.h>


SBCStatus SBC_HashCompute(VOID **handle, UINT8 *message, UINTN msglen, UINT8 *digest) 
{

  (VOID)handle;

  SBCStatus ret = SBCOK;

  SBC_RET_VALIDATE_ERRCODE((message != NULL), SBCNULLP);
  SBC_RET_VALIDATE_ERRCODE((digest != NULL), SBCNULLP);
  SBC_RET_VALIDATE_ERRCODE((msglen > 0), SBCZEROL);

  //SBC_external_mem_print_bin("SHA256 message", (UINT8 *)message, msglen);
  

  if(Sha256HashAll(message, msglen, digest) != TRUE) {
    ret =  SBCFAIL;
    goto errdone;
  }

  //SBC_external_mem_print_bin("Digest message", (UINT8 *)digest, 32);

errdone:
  return ret;
}


SBCStatus SBC_HmacCompute(VOID *handle, UINT8 *mackey, UINTN keysz,
                          UINT8 *msg, UINTN msglen, UINT8 *hmacvalue)
{
  BOOLEAN xret;
  SBCStatus ret = SBCOK;

  SBC_RET_VALIDATE_ERRCODE((handle == NULL), SBCNULLP);
  SBC_RET_VALIDATE_ERRCODE((mackey == NULL), SBCNULLP);
  SBC_RET_VALIDATE_ERRCODE(((msg == NULL) || (hmacvalue) == NULL), SBCNULLP);
  SBC_RET_VALIDATE_ERRCODE(((msglen <= 0) || (keysz <= 0)), SBCZEROL);

  xret = HmacSha256SetKey(handle, mackey, keysz);
  if(xret != TRUE) {
    eprint("HMAC SetKey fail \n");
    ret = SBCFAIL;
    goto errdone;
  }


  xret = HmacSha256Update(handle, msg, msglen);
  if(xret != TRUE) {
    eprint("HMAC Update fail \n");
    ret = SBCFAIL;
    goto errdone;
  }

  xret = HmacSha256Final(handle, hmacvalue);
  if(xret != TRUE) {
    eprint("HMAC Update fail \n");
    ret = SBCFAIL;
    goto errdone;
  }

errdone:
 return ret;

}
#ifdef SBC_HASH_UNITEST_ENABLE



VOID SBC_HashMain(VOID)
{

  UINT8 digest[32]= {0, };
  UINT8 message[32]= {0, };
  UINT8 baseanswer[32]= {0, };
  UINT32 convlen = 0;

  typedef struct  {
    CHAR8* msg;
    CHAR8* answer;
    UINTN  len;
  }SBCHashTestVectorMsg_t;

  SBCHashTestVectorMsg_t Sha256Vector[] = {
    {
        .msg = "00",
        .answer = "6e340b9cffb37a989ca544e6bb780a2c78901d3fb33738768511a30617afa01d",
        .len = 1
    },
    {
        .msg = "f0",
        .answer = "fde502858306c235a3121e42326b53228b7ef4690eeed92a2b2eafe73c03a3ef",
        .len = 1
    },
    {
        .msg = "caf9e6a025ed3d409008167ebd07c5a8d540dd5c0ce0",
        .answer = "4c022e54a6b0c7e8c12739d695287dbe170d57cde5852263eed82852e3bdbba4",
        .len = 22
    }
  };

  for(int x = 0; x < sizeof Sha256Vector / sizeof(SBCHashTestVectorMsg_t); x++) {

    dprint("SHA Test Count %d \n", x);
    convlen = _convert_str_to_hex((UINT8 *)Sha256Vector[x].msg, (UINT8 *)message);
    //SBC_external_mem_print_bin("Message", message, convlen);
    convlen = _convert_str_to_hex((UINT8 *)Sha256Vector[x].answer, (UINT8 *)baseanswer);
    //SBC_external_mem_print_bin("Answer", baseanswer, convlen);

    
    
    SBC_HashCompute(NULL, message, Sha256Vector[x].len, digest);
    SBC_external_mem_print_bin("Digest", digest, convlen);

    if(CompareMem((const void *)digest,(const void *)baseanswer, 32) != 0) {
      Print(L"Hash Test Count[%d]  Hash digest fail \n", x);
      continue;
    }

    Print(L"Hash Test Count[%d]  Hash digest passed ..... \n", x);
  }
  return;

}
#endif

