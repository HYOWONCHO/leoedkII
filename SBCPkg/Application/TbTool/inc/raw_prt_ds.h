#ifndef _RAW_PRT_DS_
#define _RAW_PRT_DS_

#include <stdint.h>

#include "raw_prt_addr.h"

#define RAW_PRT_HDR_MN_LEN              4
#define RAW_PRT_HDR_INFO_LEN            64
#define RAW_PRT_HDR_SKIP_LEN            46
#define RAW_PRT_HDR_BM_LEN              2
#define RAW_PRT_HDR_KM_LEN              2
#define RAW_PRT_HDR_RCVM_LEN            2
#define RAW_PRT_HDR_BTPRES_LEN          8

#pragma pack(push, 1)
typedef struct _t_raw_prt_hdr_t {
    uint32_t    magic_num; 
    uint8_t     prt_info[RAW_PRT_HDR_INFO_LEN];
    uint8_t     skip[RAW_PRT_HDR_SKIP_LEN];
    uint16_t    bm;
    uint16_t    km;
    uint16_t    rm;     /**!< Recovery Mode */
    uint8_t     bt_pres[RAW_PRT_HDR_BTPRES_LEN];
};

#pragma pack(pop) 

#endif
