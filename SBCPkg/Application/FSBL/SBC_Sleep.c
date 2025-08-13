#include <Library/TimerLib.h>
#include <LIbrary/PcdLib.h>


VOID SBC_MiliSleep(IN UINTN msec)
{
    UINTN start_tick;
    UINTN end_tick;
    UINTN cur_tick;
    UINTN tmr_freq;


    // Obtain the Timer Frequency from PCD
    tmr_freq = PcdGet64(PcdTimerFrequency);

    // Calculate the Tick cound 
    end_tick = ((UINTN)msec * tmr_freq) / 1000000;

    // Read the start value of timer count
    start_tick = GetPerformanceCounter();



    do {
        cur_tick = GetPerformanceCounter();
    } while ((cur_tick - start_tick) < end_tick);

    return;

}


VOID SBC_SecSleep(IN UINTN sec)
{
    UINTN  _sec = sec * 1000;

    SBC_MiliSleep(_sec);

    return;

}
