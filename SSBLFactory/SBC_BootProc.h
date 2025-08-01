#ifndef __SBC_BOOT_PROC_H__
#define __SBC_BOOT_PROC_H__


//1f3f7e80-bd6b-4d83-93fa-9e614c313d3a

#define SB_PROC_ST_MAGICID              0xABCD0000

typedef enum _boot_st_t {
    SB_PROC_ST_NRMA          = SB_PROC_ST_MAGICID | 0,        /**! Secure Boot Process Status Normal */
    SB_PROC_ST_ABNRAM,
    SB_PROC_ST_UNKNOWN
}boot_st_t;

#pragma pack(1)
typedef struct _boot_proc_t {
    VOID *ldhndl;
    VOID *blkhnd;
    VOID *rawprt_hdr; 
    VOID *keyinfo;                  /*! It's point to atp_ident_t structure */
    UINTN   pvs_sw_bnk;             /*! Previously SW Bank ID */
    UINTN   curr_sw_bnk;            /*! Current SW Bank ID */
    UINT16  bm;                     /*! Boot Mode */
    UINT16  km;                     /*! Key Mode */
    UINT32   bootst;                 /*! Boot Status */
}boot_proc_t;
#pragma pack()


#endif
