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


#endif


