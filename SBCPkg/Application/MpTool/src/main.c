#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>
#include <stdint.h>
#include <getopt.h>


#include "opt.h"

int main(int argc, char *argv[])
{

    struct cmd_ctx ctx;

    if(parse_opts(argc, argv, &ctx))
        return -1;

    switch (ctx.type) {

        case CMD_DUMPIMG:
            printf("dumpimg: addr=0x%lx size=%lu\n",
                    ctx.dump_addr, ctx.dump_size);
            break;

        case CMD_LOADIMG:
            printf("loadimg: file=%s addr=0x%lx size=%lu\n",
                    ctx.file, ctx.load_addr, ctx.load_size);
            break;

        case CMD_SETPRES:
            printf("setpres: %d %c %d %c\n",
                    ctx.n1, ctx.c1, ctx.n2, ctx.c2);
            break;

        case CMD_GETPRES:
            printf("getpres\n");
            break;

        default:
            print_usage(argv[0]);
            break;
    }

    return 0;
}
