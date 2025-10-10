#ifndef SBC_PROCTED_SW_H
#define SBC_PROCTED_SW_H

#include "SBC_ErrorType.h"
#include "SBC_TypeDefs.h"

typedef struct {
    CHAR8 name[256];
    CHAR8 ver[256];
    UINTN sw_node_off;
} sw_path_t;

typedef struct {
    UINT8 status;
    UINT8 pos;
    UINT8 sw0;
    UINT8 sw1;
    UINT8 reserved[12];
    UINTN sw0_off;
    UINTN sw1_off;
} sw_node_t;

typedef enum {
    AT_RP_SW_NODE_SLOT0 = 0,
    AT_RP_SW_NODE_SLOT1 = 1,
} AT_RP_SW_NODE_SLOT_T;

#define SBC_AT_RP_SW_NAME_MAX           256
#define SBC_AT_RP_SYS_CONF_MAX_LEN   16 * 1024
#define SBC_AT_RP_PROFILE_MAX_LEN    4096
#define SBC_AT_RP_SW_BLOCK_LEN       1024
#define SBC_AT_RP_SW_PATH_MAX        58  /** 16K * sizeof(sw_path_t) **/
#define SBC_AT_RP_SW_NAME_MAX        256
#define SBC_AT_RP_CERT_MAX_LEN       2 * 1024

#define SBC_AT_RP_AAD_LENGTH		 20
#define SBC_AT_RP_TAG_LEN	         16
#define SBC_AT_RP_IV_LEN             12
#define SBC_AT_RP_KEY_LEN            32
#define SBC_AT_RP_RES_LEN            16


/*!
 * \fn SBCStatus SBC_ProtSWGetCnt(VOID *handle, UINTN *cnt)
 * 
 * \brief 
 * 
 * \author leoc (9/25/25)
 * 
 * \param[in] handle Pointer to  Boot Proc Structure
 * \param[out] cnt   Number of count for Protected SW 
 * 
 * \return SBCStatus 
 */
SBCStatus SBC_ProtSWGetCnt(VOID *handle, UINTN *cnt);

SBCStatus SBC_ProtSWDecrypt(VOID *handle, UINT8 *key, UINT8 *migkey, UINT8 *decbuf ,UINT32 *declen);

SBCStatus SBC_RecryptoProtectedSW(VOID *handle, UINTN ofs,  UINT8* sw_secret_key, UINT8 *sw_mig_key);

SBCStatus SBC_ReadProtectedSwSlotOffset(VOID *handle, UINTN *check, CHAR8 *sw_name, UINTN slot, UINTN *offset);

SBCStatus SBC_UpdateProtectedSWListVersion(VOID *handle, CHAR8 *sw_name, CHAR8 *sw_ver);

SBCStatus SBC_UpdateProtecteSWSlotInfo(VOID *handle, CHAR8 *sw_name);

SBCStatus SBC_FindProtectedSw(VOID *handle, CHAR8 name[256], CHAR8 *ver, UINTN *sw_node_off);

SBCStatus SBC_WriteProtSwNodeBlob(VOID *handle, UINTN swoff, UINT8 *blob, UINTN blob_len, UINT8 *iv, UINT8 *tag);

SBCStatus SBC_WriteProtSwSize(VOID *handle, UINTN sw_off, UINTN size);

SBCStatus SBC_GetProtectedSwName(VOID *handle, UINTN st, CHAR8 *sw_name, UINTN sw_name_size);

SBCStatus SBC_LoadSysFile(VOID *handle, UINTN offset, UINT8 *deckey, UINT8* data);

#endif

