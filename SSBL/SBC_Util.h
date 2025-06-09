#ifndef _SBC_UTIL_
#define _SBC_UTIL_
#include <string.h>
#include "SBC_Log.h"

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
