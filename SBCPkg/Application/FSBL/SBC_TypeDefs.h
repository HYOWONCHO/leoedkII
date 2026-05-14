#ifndef __SBCTYPEDEFS_
#define __SBCTYPEDEFS_

#include "SBC_Log.h"

#include <Library/BaseMemoryLib.h>
#include <Library/MemoryAllocationLib.h>

#define SBC_BOOT_DISCOVER_FROM_REOCVERY                         0x0001


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

typedef struct _atlv_t {
    UINT32      length;
    UINT8       data[0];
}atlv_t; 


#define SBCUNUSED           [[maybe_unused]]
//#define SBCUNUSED_VAR(x)    UNUSED_VAR(x)
//#define SBCUNUSED       [[gnu::unused]]
//#define SBCUNUSED       __attribute__((unused))

#define SBC_CREATE_ATLV(_lv, _data, _len)                               \
    do{                                                                 \
        (_lv) = NULL;                                                   \
                                                                        \
        if( (_data) != NULL && (_len) > 0 ) {                           \
            (_lv) = AllocatePool(sizeof(*(_lv)) + (_len));              \
                                                                        \
            if( (_lv) != NULL ) {                                       \
                ZeroMem((_lv), (_len));                                 \
                (_lv)->length = (_len);                                 \
                                                                        \
                if( (_data) != NULL ) {                                 \
                    CopyMem(((_lv)->data), (_data), (_len));            \
                };                                                      \
            }                                                           \
        }                                                               \
    }while( 0 )

static inline void _lv_set_data(LV_t *lv, void *buf, int bufl)
{
  lv->value = buf;
  lv->length = bufl;
}
#if 1
static inline void * sbc_atlv_alloc_copy(
    IN CONST void *Data OPTIONAL,
    IN UINT32      Length
)
{
    void *buf;

    if (Length == 0) {
        return NULL;
    }

    buf = AllocatePool(Length + sizeof(((atlv_t *)0)->length));
    if( buf == NULL ) {
        return NULL;
    }

    ZeroMem(buf, Length + sizeof(((atlv_t *)0)->length)); 
    ((atlv_t *)buf)->length = Length;


    if (Data != NULL) {
        CopyMem(((atlv_t *)buf)->data, Data, Length);
    }

    return buf;
}
#else
static inline void *
sbc_atlv_alloc_copy(
    IN CONST void *Data OPTIONAL,
    IN UINT32      Length
)
{
    atlv_t *lv;

    if (Length == 0)
        return NULL;

    lv = AllocateZeroPool(sizeof(*lv) + Length);
    if (lv == NULL)
        return NULL;

    lv->length = Length;

    if (Data != NULL)
        CopyMem(lv->data, Data, Length);

    return lv;
}
#endif


#endif


