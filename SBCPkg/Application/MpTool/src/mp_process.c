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
                "Failed to read the Raw Partition( %s:0x%lx ) \n",
                ctx->dev_path, ctx->dump_addr);
        return ret;
    }

    hex_dump("Loaded ...", (const void *)buf, ctx->dump_size);

    return 0;
}


ssize_t set_boot_pres(void *_ctx)
{
    struct cmd_ctx *ctx = (struct cmd_ctx *)_ctx;
    uint8_t pres_buf[4] = {0, };
    ssize_t ret = -1;

    ret = raw_read(ctx->dev_path,
                    (void *)pres_buf,
                    4,
                    0x00000078);

    if(ret < 0) {
        fprintf(stderr, 
                "Failed to read the pres for boot bank \n");
        return ret;
    }
#if 0
    printf("%d:%02x %d:%c %d:%02x %d:%c \n",
            0, pres_buf[0], 
            1, pres_buf[1], 
            2, pres_buf[2], 
            3, pres_buf[3]);
#endif    
    pres_buf[0] = ctx->n1;
    pres_buf[1] = ctx->c1;
    pres_buf[2] = ctx->n2;
    pres_buf[3] = ctx->c2;

    ret =raw_write(ctx->dev_path,
                    (const void *)pres_buf,
                    4,
                    0x78);

    if(ret < 0) {
        fprintf(stderr, 
                "Failed to write the pres for boot bank \n");
        return ret;
    }

    memset(pres_buf, 0x0, 4);

    ret = raw_read(ctx->dev_path,
                    (void *)pres_buf,
                    4,
                    0x00000078);

    if(ret < 0) {
        fprintf(stderr, 
                "Failed to read the pres for boot bank, after write \n");
        return ret;
    }

    hex_dump("Boot Pres Set-up", (const void *)pres_buf, 4);

    

    return ret;

errdone:
    return ret;

}


