#include "raw_device_ctrl.h"
#include "mp_process.h"




ssize_t dump_image_from_rawprt(void *_ctx, void **out_buf)
{
    struct cmd_ctx *ctx = (struct cmd_ctx *)_ctx;
    ssize_t ret = -1;
    uint8_t *buf = NULL;


    if(ctx->dump_size <= 0) {
        fprintf(stderr, 
                "Invalid Length for Image dump (%d) \n",
                ctx->dump_size);
        return ret;
    }

    buf = calloc(ctx->dump_size, sizeof(uint8_t));
    if(!buf) {
        perror("calloc");
        return ret; 
    }



    ret = raw_read(ctx->dev_path,
                    (void *)buf,
                    ctx->dump_size,
                    ctx->dump_addr);

    if(ret < 0) {
        fprintf(stderr, 
                "Raw Partition Read ( %s:0x%lx ) \n",
                ctx->dev_path, ctx->dump_addr);
        return ret;
    }

    hex_dump("Image Dump", (const void *)buf, ctx->dump_size);




    return 0;



}


