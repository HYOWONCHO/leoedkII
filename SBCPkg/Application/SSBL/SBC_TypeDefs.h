#ifndef __SBCTYPEDEFS_
#define __SBCTYPEDEFS_

#include "SBC_Log.h"

#ifndef  off_t
typedef UINTN   off_t;
#endif




/**<! X_RET_VALIDATE_ERRCODE set errno and return error code*/
#define SBC_RET_VALIDATE_ERRCODE( expr , errorcode )							\
	({																			\
		int _expr_val=!!(expr);													\
		if( !(_expr_val) )	{													\
			ret = errorcode;													\
            dprint("'%a' FAILED.", #expr);                                      \
			goto errdone;   													\
		}																		\
	})

/**<! X_RET_VALIDATE_ERRCODE set errno and return error code*/
#define SBC_RET_VALIDATE_ERRCODEMSG( expr , errorcode, msg )				    \
	({																			\
		int _expr_val=!!(expr);													\
		if( !(_expr_val) )	{													\
			ret = errorcode;													\
            dprint("'%a' FAILED. : %a", #expr, #msg);                           \
			goto errdone;   													\
		}																		\
	})

struct _tlv_t {
    UINT16      tag;
    UINT32      length;
    VOID        *value;
};

typedef struct _tlv_t TLV_t;
typedef struct _tlv_t *TLV_p;



struct _lv_t {
    UINT32      length;
    VOID        *value;
};

typedef struct _lv_t LV_t;
typedef struct _lv_t *LV_p;

#pragma pack(1)
typedef struct _aes_buf_t{
    VOID *key;
    VOID *iv;
    VOID *tag;
    VOID *buf;
}aes_buf_t;
#pragma pack()


#define KDF_KEY_MAXL                (32)
typedef struct _kdf_t {
    UINT8   ikm[KDF_KEY_MAXL];
    UINTN   ikml;
    UINT8   salt[KDF_KEY_MAXL];
    UINTN   saltl;
    UINT8   info[KDF_KEY_MAXL];   
    UINTN   infol;    
}kdf_t;


#define SBCUNUSED           [[maybe_unused]]
//#define SBCUNUSED_VAR(x)    UNUSED_VAR(x)
//#define SBCUNUSED       [[gnu::unused]]
//#define SBCUNUSED       __attribute__((unused))


#define SBC_UC_MODE_UPDATE              0xAA000001
#define SBC_UC_MODE_RECOVERY            0xAA000002
#define SBC_UC_MODE_NORMAL              0xAA000003
#define SBC_UC_MODE_FACTORY             0xAA000003

static inline void _lv_set_data(LV_t *lv, void *buf, int bufl)
{
  lv->value = buf;
  lv->length = bufl;
}


#endif


