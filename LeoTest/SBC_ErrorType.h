#ifndef __SBCErrorType
#define __SBCErrorType

#include <Library/UefiLib.h>
#include "SBC_TypeDefs.h"
#include "SBC_Log.h"

typedef enum {
   SBCOK                = 0,
   SBCFAIL              = 300,
   SBCINVPARAM          = 301,  /*<! Invalid parameter */
   SBCNULLP             = 302,  /*<! NULL ptr*/
   SBCZEROL             = 303,  /*<! Length is zero */
   SBCNOTFND            = 304,  /*<! Not found*/
   SBCBADFMT            = 305,  /*<! Bad format*/
   SBCFMMTTYP           = 306,  /*<! Bad format type*/
   SBCNOSPC             = 307,  /*<! Not enouth space for outptu*/
   SBCIO                = 308,  /*<! I/O error */
   SBCFAULT             = 309,  /*<! Bad Address*/
   SBCBUSY              = 310,  /*<! Busy Status*/
   SBCTIME              = 311,  /*<! Timer expire*/
   SBCCOMM              = 312,  /*<! Communication error */
   SBCPROTO             = 313,  /*<! Protocol error*/
   SBCNOTSUP            = 314,  /*<! Not Support*/
   SBCENCFAIL           = 315,
   SBCDECFAIL           = 316,
   SBCUNKNOWN
}SBCStatus;





#endif
