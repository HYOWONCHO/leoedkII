#ifndef _SBC_ANTITAMPERING_
#define _SBC_ANTITAMPERING_


SBCStatus SBC_BaseAnswerEncryptStore(UINT8 *out, UINTN *outl);
SBCStatus  SBC_BaseAnswerValidate(UINT8 *answer, UINTN answerl);

#endif
