#ifndef _MP_PROCESS_H_
#define _MP_PROCESS_H_


#include "log_print.h"



ssize_t dump_image_from_rawprt(void *_ctx, void **out_buf);
ssize_t set_boot_pres(void *_ctx);
#endif
