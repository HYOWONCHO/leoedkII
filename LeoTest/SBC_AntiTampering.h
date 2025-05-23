#ifndef _SBC_ANTITAMPERING_
#define _SBC_ANTITAMPERING_



typedef struct _hw_unique_info_t {
    UINT8   mbsn[64];            /*!< Motherboard serail */
    UINTN   mbsnl;
    UINT8   mmsn[64];            /*!< Memory serial */
    UINTN   mmsnl;
    UINT8   hdsn[64];            /*!< SSD serial */
    UINTN   hdsnl;           /*!< Length of  SSD serial */
    //at_key_t *key;
}hw_uniqueinfo_t;

SBCStatus SBC_GenDeviceID(UINT8 *devid);
SBCStatus SBC_BaseAnswerEncryptStore(UINT8 *out, UINTN *outl);
SBCStatus  SBC_BaseAnswerValidate(UINT8 *answer, UINTN answerl);

#endif
