#ifndef _SBC_TIMER_H_
#define _SBC_TIMER_H_

#include "SBC_Log.h"

/*!
 * \code
 *
 *      STATIC
        TIME_RESULT
        TimeFunctionCall(UEFI_TASK_FN Fn, VOID *Context) {
          TIME_RESULT R;
          UINT64 t0 = PerfNowTicks();
          R.Status = Fn(Context);
          UINT64 t1 = PerfNowTicks();
          R.Ticks = PerfDeltaTicks(t0, t1);
          R.NanoSeconds = PerfTicksToNs(R.Ticks);
          return R;
        }
 *    VOID ExampleBlockTiming(VOID) {
 *     UINT64 ns = 0;
 *     TIME_BLOCK_NS(ns, {
 *       // Here is the code you want to measure
 *       // gBS->Stall(500);  // 예: 500us 지연
 *     });
 *     LogElapsed(L"BlockWork", ns);
 *   }
 * \endcode
 */
#define SBC_TIME_BLOCKS_NS(_ns_var_, _code_block_)				            \
    ({                                                                      \
        UINTN __t0 = SBC_PerfNowTicks();                                    \
        { _code_block_; }                                                   \
        UINTN __t1 = SBC_PerfNowTicks();                                    \
        (_ns_var_) = SBC_PerfTicksTons(_PerfDeltaTicks(__t0, __t1));        \
    })


/**
 * @fn      UINTN _PerfDeltaTicks(UINTN T0, UINTN T1)
 *
 * @brief   Calculate elapsed performance counter ticks between two timestamps.
 *
 * @param[in] T0
 *        Initial performance counter value.
 *
 * @param[in] T1
 *        Final performance counter value.
 *
 * @return  Elapsed performance counter ticks between T0 and T1.
 *
 * @note
 * - This function assumes both T0 and T1 are obtained from
 *   GetPerformanceCounter().
 * - The returned value represents raw counter ticks and must be converted
 *   to time units (e.g., nanoseconds) using GetTimeInNanoSecond().
 */
UINTN _PerfDeltaTicks(UINTN T0, UINTN T1);

/**
 * @fn      UINTN SBC_PerfNowTicks(VOID)
 *
 * @brief   Retrieve the current performance counter value.
 *
 * @return  Current performance counter tick value.
 */
UINTN SBC_PerfNowTicks(VOID);

/**
 * @fn      UINTN SBC_PerfTicksTons(UINTN ticks)
 *
 * @brief   Convert performance counter ticks to nanoseconds.
 * 
 * @param[in] ticks
 *        Performance counter ticks to convert.
 *
 * @return  Time value in nanoseconds corresponding to the input ticks.
 */
UINTN SBC_PerfTicksTons(UINTN ticks);

///**
// * @fn      UINTN SBC_TIME_BLOCKS_NS(UINTN (*Func)(VOID *Ctx), VOID *Ctx)
// *
// * @brief   Measure execution time of a function in nanoseconds.
// *
// * @param[in] Func
// *        Function pointer to the code to be measured.
// *
// * @param[in] Ctx
// *        Optional user context passed to the target function.
// *        May be NULL if unused.
// *
// * @return  Elapsed execution time in nanoseconds.
// *
// * @note
// * - The target function is executed exactly once.
// * - This implementation is debugger-friendly and portable across compilers.
// * - Internally uses SBC_PerfNowTicks(), _PerfDeltaTicks(),
// *   and SBC_PerfTicksTons().
// *
// * @example
// * @code
// * static UINTN TestFunc(VOID *Ctx)
// * {
// *     UINTN *val = (UINTN *)Ctx;
// *     (*val)++;
// *     return 0;
// * }
// *
// * UINTN elapsed_ns;
// * UINTN counter = 0;
// *
// * elapsed_ns = SBC_TimeBlockNs(TestFunc, &counter);
// *
// * dprint("Elapsed time: %lu ns\n", elapsed_ns);
// * @endcode
// */
//static inline UINTN
//SBC_TIME_BLOCKS_NS(UINTN (*Func)(VOID *Ctx), VOID *Ctx)
//{
//    UINTN t0 = SBC_PerfNowTicks();
//    (void)Func(Ctx);
//    UINTN t1 = SBC_PerfNowTicks();
//
//    return SBC_PerfTicksTons(_PerfDeltaTicks(t0, t1));
//}


#endif
