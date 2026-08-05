#ifndef _SBC_SLEEP_H_
#define _SBC_SLEEP_H_



/*!
 * \fn VOID SBC_MiliSleep(IN UINTN msec)
 *
 * \brief Suspend execution from millisecond intervals
 * 
 * \author leonc (8/13/25)
 * 
 * \param msec   
 */
VOID SBC_MiliSleep(IN UINTN msec);

/*!
 * \fn VOID SBC_SecSleep(IN UINTN sec)
 *
 * \brief Suspend execution from second intervals
 * 
 * \author leonc (8/13/25)
 * 
 * \param msec   
 */
VOID SBC_SecSleep(IN UINTN sec);



#endif

