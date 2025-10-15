#ifndef _SBC_TIMER_H_
#define _SBC_TIMER_H_



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
    ({										                                \
    	UINTN __t0 = SBC_PerfNowTicks();					                \
    	{ _code_block_; }							                        \
    	UINTN __t1 = SBC_PerfNowTicks();					                \
    	(_ns_var_) = SBC_PerfTicksTons(_PerfDeltaTicks(__t0, __t1));        \
    })	



UINTN _PerfDeltaTicks(UINTN T0, UINTN T1);
UINTN SBC_PerfNowTicks(VOID);
UINTN SBC_PerfTicksTons(UINTN ticks);





#endif
