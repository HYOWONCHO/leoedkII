#ifndef __SBC_BOOT_PROC_H__
#define __SBC_BOOT_PROC_H__

#pragma pack(1)
typedef struct _boot_proc_t {
    VOID *ldhndl;
    VOID *blkhnd;
    VOID *keyinfo;                  /*! It's point to atp_ident_t structure */
    UINTN   pvs_sw_bnk;             /*! Previously SW Bank ID */
    UINTN   curr_sw_bnk;            /*! Current SW Bank ID */
    UINT16  bm;                     /*! Boot Mode */
    UINT16  km;                     /*! Key Mode */
}boot_proc_t;
#pragma pack()


#endif
