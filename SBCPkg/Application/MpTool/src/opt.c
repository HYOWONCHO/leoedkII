#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <getopt.h>

#include "opt.h"

static struct option long_opts[] = {
    { "dumpimg", required_argument, 0, 1 },
    { "loadimg", required_argument, 0, 2 },
    { "setpres", required_argument, 0, 3 },
    { "getpres", no_argument,       0, 4 },
    { 0, 0, 0, 0 },
};

void print_usage(const char *prog)
{
    printf("Usage:\n");
    printf("  %s --dumpimg <hex_addr> <size>\n", prog);
    printf("  %s --loadimg <file> <hex_addr> <size>\n", prog);
    printf("  %s --setpres <n1> <c1> <n2> <c2>\n", prog);
    printf("  %s --getpres\n", prog);
}

int parse_opts(int argc, char *argv[], struct cmd_ctx *ctx)
{
    int opt;
    int idx = 0;

    memset(ctx, 0, sizeof(*ctx));

    optind = 1;

    while ((opt = getopt_long(argc, argv, "", long_opts, &idx)) != -1) {

        switch (opt) {
        case 1: /* dumpimg */
            if (optind + 1 > argc) {
                print_usage(argv[0]);
                return -1;
            }
            ctx->type = CMD_DUMPIMG;
            ctx->dump_addr = strtoul(optarg, NULL, 16);
            ctx->dump_size = strtoul(argv[optind], NULL, 0);
            optind++;
            return 0;

        case 2: /* loadimg */
            if (optind + 2 > argc) {
                print_usage(argv[0]);
                return -1;
            }
            ctx->type = CMD_LOADIMG;
            ctx->file = optarg;
            ctx->load_addr = strtoul(argv[optind], NULL, 16);
            ctx->load_size = strtoul(argv[optind + 1], NULL, 0);
            optind += 2;
            return 0;

        case 3: /* setpres */
            if (optind + 3 > argc) {
                print_usage(argv[0]);
                return -1;
            }
            ctx->type = CMD_SETPRES;
            ctx->n1 = atoi(optarg);
            ctx->c1 = argv[optind][0];
            ctx->n2 = atoi(argv[optind + 1]);
            ctx->c2 = argv[optind + 2][0];
            optind += 3;
            return 0;

        case 4: /* getpres */
            ctx->type = CMD_GETPRES;
            return 0;

        default:
            print_usage(argv[0]);
            return -1;
        }
    }

    print_usage(argv[0]);
    return -1;
}

