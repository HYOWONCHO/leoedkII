#ifndef _UNIT_TEST_H_
#define _UNTI_TEST_H_

#define SB_PROC_ST_MAGICID              0xABCD0000

typedef enum _boot_st_t {
    SB_PROC_ST_NRMA          = SB_PROC_ST_MAGICID | 0,        /**! Secure Boot Process Status Normal */
    SB_PROC_ST_ABNRAM,
    SB_PROC_ST_UNKNOWN
}boot_st_t;

#pragma pack(1)
typedef struct _unit_proc_t {
    VOID        *ldhndl;
    VOID        *blkhnd;
    VOID        *rawprt_hdr; 
    VOID        *baseansr;
    VOID        *keyinfo;                   /*! It's point to atp_ident_t structure */
    VOID        *dice;
    UINTN       pvs_sw_bnk;                 /*! Previously SW Bank ID */
    UINTN       curr_sw_bnk;                /*! Current SW Bank ID */
    UINT16      bm;                         /*! Boot Mode */
    UINT16      km;                         /*! Key Mode */
    UINT32      bootst;                     /*! Boot Status */
    UINT16      rcvmode;
    VOID        *imghndl;
    BOOLEAN     is_factory;
}unit_proc_t;

typedef unit_proc_t boot_proc_t;
#pragma pack()


#ifdef _UNIT_TEST_ON_
void D_SAT_PWT_SFR_001(void *priv);
void D_SAT_PWT_SFR_002(void *priv);
void D_SAT_PWT_SFR_003(void *priv);
void D_SAT_PWT_SFR_003_Tampre(void *priv);
void D_SAT_PWT_SFR_006_FSBL(void *priv);

void SBC_UnitTestSFR001_TO_003(void *priv);
void SBC_UnitFsblNormalTamperTest(void *priv);
#endif


#endif
