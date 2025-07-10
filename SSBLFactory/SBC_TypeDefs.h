#ifndef __SBCTYPEDEFS_
#define __SBCTYPEDEFS_

#include "SBC_Log.h"


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

static inline void _lv_set_data(LV_t *lv, void *buf, int bufl)
{
  lv->value = buf;
  lv->length = bufl;
}


#endif


