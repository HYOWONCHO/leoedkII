#ifndef _SBC_UTIL_
#define _SBC_UTIL_
#include <string.h>
#include "SBC_Log.h"


#define SBC_SWAP_ENDIAN_16(val) \
    (((UINT16)(val) & 0xFF00) >> 8) | \
    (((UINT16)(val) & 0x00FF) << 8)


#define SBC_SWAP_ENDIAN_32(val) \
    (((UINT32)(val) & 0xFF000000UL) >> 24) | \
    (((UINT32)(val) & 0x00FF0000UL) >> 8)  | \
    (((UINT32)(val) & 0x0000FF00UL) << 8)  | \
    (((UINT32)(val) & 0x000000FFUL) << 24)


#define SBC_SWAP_ENDIAN_64(val) \
    (((UINTN)(val) & 0xFF00000000000000ULL) >> 56) | \
    (((UINTN)(val) & 0x00FF000000000000ULL) >> 40) | \
    (((UINTN)(val) & 0x0000FF0000000000ULL) >> 24) | \
    (((UINTN)(val) & 0x000000FF00000000ULL) >> 8)  | \
    (((UINTN)(val) & 0x00000000FF000000ULL) << 8)  | \
    (((UINTN)(val) & 0x0000000000FF0000ULL) << 24) | \
    (((UINTN)(val) & 0x000000000000FF00ULL) << 40) | \
    (((UINTN)(val) & 0x00000000000000FFULL) << 56)



/**
 * Convert the ASCII value to Hex value
 * 
 * @author leoc (5/9/25)
 * 
 * @param val    
 * 
 * @return STATIC UINT32 
 */
STATIC inline UINT32 _calculate_hex_posval(UINT8 val)
{
  UINT32 ret = 0;
  switch(val) {
  case '0' ... '9':
    ret = val - 48;
    break;
  case 'a' ... 'f':
    ret = val - 87;
    break;
  case 'A' ... 'F':
    ret = val - 55;
    break;
  default:
    dprint("Unknown Hex character (%x)", val);
    ret = 0;
    break;
  }

  return ret;

}

/**
 * Fill the hex value in User specified buffer
 * 
 * 
 * @author leoc (5/9/25)
 * 
 * @param src    Pointer to String 
 * @param dest   
 * 
 * @return STATIC UINT32
 * @note
 *  This function JUST call when Crypto Test behavior
 */
STATIC inline UINT32 _convert_str_to_hex(UINT8 *src, UINT8 *dest)
{

  UINTN complen = 0;
  UINT32 cnt = 0;
  UINT32 temp;

  complen = strlen((CONST CHAR8* )src);

  for(int x = 1; x < complen + 1; x++) {
    temp = _calculate_hex_posval(src[x-1]);
    if(x%2 == 0) {
      dest[cnt] |= temp & 0xF; 
      cnt++;
      continue;
    }

    dest[cnt] = (temp << 4)& 0xF0;
  }

  if(complen % 2 != 0) {
    cnt += complen % 2;
  }

  return cnt;

}




#endif
