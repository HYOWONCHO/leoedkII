#include <Uefi.h>
#include <Library/TimerLib.h>
#include <Library/PrintLib.h>
#include <Library/DebugLib.h>


UINTN _PerfDeltaTicks(UINTN T0, UINTN T1)
{
#if 0
    UINT64 Start, End;
    (void)GetPerformanceCounterProperties(&Start, &End);

    if (Start < End) { // count-up
        if (T1 >= T0) return T1 - T0;
        // rollover
        return (End - T0) + (T1 - Start) + 1;
    } else {           // count-down
        if (T1 <= T0) return T0 - T1;
        // rollover
        return (T0 - End) + (Start - T1) + 1;
    }
#else
    return 0;
#endif
}

UINTN SBC_PerfNowTicks(VOID)
{
    return 0; //GetPerformanceCounter();
}

UINTN SBC_PerfTicksTons(UINTN ticks)
{
    return 0;  //GetTimeInNanoSecond(ticks);
}

