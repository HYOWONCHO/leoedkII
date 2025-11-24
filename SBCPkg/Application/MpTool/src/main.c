#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>
#include <stdint.h>
#include <getopt.h>


#include "opt.h"
#include "mp_process.h"

int main(int argc, char *argv[])
{

    struct cmd_ctx ctx;

    if(parse_opts(argc, argv, &ctx))
        return -1;

    switch (ctx.type) {

        case CMD_DUMPIMG:
            uint8_t *buf = NULL;
            printf("dumpimg: path=%s addr=0x%lx size=%lu\n",
                    ctx.dev_path, ctx.dump_addr, ctx.dump_size);

            dump_image_from_rawprt(&ctx, &buf);
            if(buf) {
                free(buf);
                buf = NULL;
            }
            break;

        case CMD_LOADIMG:
            printf("loadimg: file=%s addr=0x%lx size=%lu\n",
                    ctx.file, ctx.load_addr, ctx.load_size);

            copy_file_to_raw((const char *)ctx.dev_path, (const char *)ctx.file);
            break;

        case CMD_SETPRES:
            printf("setpres: %d %c %d %c\n",
                    ctx.n1, ctx.c1, ctx.n2, ctx.c2);
            set_boot_pres(&ctx);
            break;

        case CMD_GETPRES:
            printf("getpres\n");
            break;

        case CMD_SETBM:
            printf("setting boot mode \n");
            break;
        case CMD_GETBM:
            printf("getting boot mode \n");s
            break;
        default:
            print_usage(argv[0]);
            break;
    }

    return 0;
}
