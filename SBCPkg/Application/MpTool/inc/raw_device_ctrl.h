#ifndef _RAW_DEVICE_CTRL_H_
#define _RAW_DEVICE_CTRL_H_


#include "log_print.h"

#define BLK_SIZE        512

int raw_read_u32(const char *dev, off_t offset, uint32_t *out);


int copy_raw_to_raw(const char *src_dev, const char *dst_dev,
               off_t src_offset, off_t dst_offset,
               size_t copy_size);


int copy_file_to_raw(const char *dev, const char *file);

ssize_t raw_read(const char *dev, void *buf, size_t size, off_t offset);

#endif
