#ifndef __SBCTYPEDEFS_
#define __SBCTYPEDEFS_

#include "SBC_Log.h"

#ifndef  off_t
typedef UINTN   off_t;
#endif




/**<! X_RET_VALIDATE_ERRCODE set errno and return error code*/
#if 0
#define SBC_RET_VALIDATE_ERRCODE( expr , errorcode )							\
	({																			\
		int _expr_val=!!(expr);													\
		if( !(_expr_val) )	{													\
			ret = errorcode;													\
            dprint("'%a' FAILED.", #expr);                                      \
			goto errdone;   													\
		}																		\
	})
#else
/**
 * @def SBC_RET_VALIDATE_ERRCODE
 * @brief Validates an expression and handles error reporting with a custom message.
 *
 * @param expr       The expression to validate (e.g., pointer != NULL).
 * @param errorcode  The error code to assign to `ret` if the validation fails.
 *
 */
#define SBC_RET_VALIDATE_ERRCODE(expr, errorcode)         \
    do {                                                  \
        if (!(expr)) {                                    \
            ret = (errorcode);                            \
            dprint("'%a' FAILED.", #expr);                \
            goto errdone;                                 \
        }                                                 \
    } while (0)
#endif


#if 0
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
#else
/**
 * @def SBC_RET_VALIDATE_ERRCODEMSG
 * @brief Validates an expression and handles error reporting with a custom message.
 *
 * @param expr       The expression to validate (e.g., pointer != NULL).
 * @param errorcode  The error code to assign to `ret` if the validation fails.
 * @param msg        A custom message string describing the failure context.
 *
 */
#define SBC_RET_VALIDATE_ERRCODEMSG(expr, errorcode, msg)         \
    do {                                                          \
        if (!(expr)) {                                            \
            ret = (errorcode);                                    \
            dprint("'%a' FAILED: %a\n", #expr, msg);              \
            goto errdone;                                         \
        }                                                         \
    } while (0)
#endif


/**
 * @struct _tlv_t
 * @brief Represents a Tag-Length-Value (TLV) formatted data block.
 *
 * This structure is used to encapsulate a unit of data in TLV format, commonly used in
 * configuration blobs, secure boot metadata, or protocol messages.
 *
 * @var tag
 *      A 16-bit identifier representing the type or category of the data.
 *
 * @var length
 *      A 32-bit unsigned integer indicating the size (in bytes) of the value field.
 *
 * @var value
 *      A pointer to the actual data payload associated with the tag.
 */
struct _tlv_t {
    UINT16      tag;
    UINT32      length;
    VOID        *value;
};

/**
 * @typedef TLV_t
 * @brief Alias for the `_tlv_t` structure representing a Tag-Length-Value data block.
 */
typedef struct _tlv_t TLV_t;

/**
 * @typedef TLV_p
 * @brief Pointer to a TLV_t structure.
 */
typedef struct _tlv_t *TLV_p;



/**
 * @struct _lv_t
 * @brief Represents a Tag-Length-Value (TLV) formatted data block.
 *
 * This structure is used to encapsulate a unit of data in TLV format, commonly used in
 * configuration blobs, secure boot metadata, or protocol messages.
 *
 * @var length
 *      A 32-bit unsigned integer indicating the size (in bytes) of the value field.
 *
 * @var value
 *      A pointer to the actual data payload associated with the tag.
 */
struct _lv_t {
    UINT32      length;
    VOID        *value;
};


/**
 * @typedef LV_t
 * @brief Alias for the `_lv_t` structure representing a
 *        Tag-Length-Value data block.
 */
typedef struct _lv_t LV_t;

/**
 * @typedef LV_p
 * @brief Pointer to a LV_t structure.
 */
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

/**
 * @struct kdf_t
 * @brief Represents input parameters for a Key Derivation Function (KDF).
 *
 * @var ikm
 *      Input Keying Material (IKM). Raw secret input used as the base for key derivation.
 *
 * @var ikml
 *      Length of the IKM in bytes.
 *
 * @var salt
 *      Optional salt value used to randomize the derivation process and prevent dictionary attacks.
 *
 * @var saltl
 *      Length of the salt in bytes.
 *
 * @var info
 *      Optional context-specific information (e.g., usage label, application ID).
 *
 * @var infol
 *      Length of the info field in bytes.
 *
 */
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


/**
 * @fn _lv_set_data
 * @brief Initializes an LV_t structure with a buffer and its length.
 *
 * @param[out] lv     Pointer to the LV_t structure to initialize.
 * @param[in]  buf    Pointer to the data buffer to assign.
 * @param[in]  bufl   Length of the buffer in bytes.
 */
static inline void _lv_set_data(LV_t *lv, void *buf, int bufl)
{
  lv->value = buf;
  lv->length = bufl;
}


#endif


