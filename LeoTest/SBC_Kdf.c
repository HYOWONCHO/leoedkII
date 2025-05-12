#include <Library/BaseCryptLib.h>

#include "SBC_ErrorTypes.h"

/**
 * @brief Generate the RNG
 *
 * @param[in]   seed      Random seed buffer
 * @param[in]   szseed    Length of seed buffer
 * @param[in]   szrng     Number of Random size
 * @param[out]  rngdata   Random data
 *
 * @return  On success, return the SBCOK, otherwise return approiate value
 */
SBCStatus SBC_RngGeneration(UINT8 *seed, UINTN szseed, UINTN szrng, UINT8 *rngdata) 
{

  BOOLEAN status = TRUE;


  if(seed == NULL || rngdata == NULL) {
    Print(L"%s args point to NULL \n", __FUNCTION__);
    return SBCNULLP;
  }

  if(szseed <= 0 || szrng <= 0) {
    Print(L"%s arg has length os zero \n");
    return SBCZEROL;
  }



  status = RandomSeed(seed, szseed);
  if(status == FALSE) {
    Print(L"RandomSeed fail \n");
    return SBCFAIL;
  }

  status = RandomBytes(rngdata, szrng);
  if(status != TRUE) {
    Print(L"RandomBytes fail \n");
    return SBCFAIL;
  }

  return SBCOK;



}

