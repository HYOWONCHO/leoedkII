#ifndef _RAW_PRT_ADDR_
#define _RAW_PRT_ADDR_


#define RAW_PRT_HDR_START               0x00000000
#define RAW_PRT_HDR_MAGIC_ADDR              RAW_PRT_HDR_START
#define RAW_PRT_HDR_INFO_ADDR               RAW_PRT_HDR_START + 4
#define RAW_PRT_HDR_RESERVED_1              RAW_PRT_HDR_INFO_ADDR + 64 
#define RAW_PRT_HDR_BM_ADDR                 RAW_PRT_HDR_RESERVED_1 + 46
#define RAW_PRT_HDR_KM_ADDR                 RAW_PRT_HDR_BM_ADDR + 2
#define RAW_PRT_HDR_RCVM_ADDR               RAW_PRT_HDR_KM_ADDR + 2
#define RAW_PRT_HDR_BOOTPRES_ADDR           RAW_PRT_RCVM_ADDR + 2







#endif
