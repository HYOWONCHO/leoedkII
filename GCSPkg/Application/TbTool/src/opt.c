#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <getopt.h>

#include "opt.h"
#include "raw_device_ctrl.h"

static struct option long_opts[] = {
    { "dumpimg", required_argument, 0, 1 },
    { "loadimg", required_argument, 0, 2 },
    { "setpres", required_argument, 0, 3 },
    { "getpres", no_argument,       0, 4 },
    { "setbkm", required_argument, 0, 5 },
    { "getbkm", no_argument,       0, 6 },
    { 0, 0, 0, 0 },
};

void print_usage(const char *prog)
{
    printf(MAGENTA "Usage:\n");
    printf("  %s --dumpimg <device path> <hex_addr> <size>\n", prog);
    printf("  %s --loadimg <device path> <file> <hex_addr> <size>\n", prog);
    printf("  %s --setpres <device_path> <n1> <c1> <n2> <c2>\n", prog);
    printf("  %s --getpres <device_path>\n", prog);
    printf("  %s --setbkm <device path> <boot mode> <key mode>\n", prog);
    printf("  %s --getbkm <device path> \n" RESET, prog);
}




int parse_opts(int argc, char *argv[], struct cmd_ctx *ctx)
{
    int opt, idx = 0;
    int optind_pass = 0;

    memset(ctx, 0, sizeof(*ctx));

    /* 첫 번째 인자는 항상 dev_path 이어야 한다 */
    if (argc < 3) {  /* 최소: <tool> <dev> <option> */
        //printf("argc : %d \n", argc);
        print_usage(argv[0]);
        return -1;
    }

    //argv++;
    ctx->dev_path = argv[2];

    /* getopt_long 시작 위치를 dev_path 이후로 설정 */
    //optind = 2;
    optind = 1;

    while ((opt = getopt_long(argc, argv, "", long_opts, &idx)) != -1) {

        //printf("opt pargins : %d \n", opt);
        switch (opt) {

            case 1: /* dumpimg */
                //printf("dumping : %d , argc :%d optarg : %s\n", optind, argc, optarg);
                if (optind >= argc) {
                    print_usage(argv[0]);
                    return -1;
                }
                ctx->type = CMD_DUMPIMG;
                //ctx->dump_addr = strtoul(optarg, NULL, 16);
                ctx->dump_addr = strtoul(argv[optind++], NULL, 16);
                ctx->dump_size = strtoul(argv[optind], NULL, 0);

                //printf("dump addr : 0x%lx, size : %ld \n", 
                //        ctx->dump_addr, ctx->dump_size);
                //optind++;
                return 0;

            case 2: /* loadimg */
                //printf("loading : %d \n", opt);
                if (optind + 1 >= argc) {
                    print_usage(argv[0]);
                    return -1;
                }
                ctx->type = CMD_LOADIMG;
                //printf("%s:%d \n", __FUNCTION__, __LINE__);
                ctx->file      = argv[optind++];
                //printf("%s:%d \n", __FUNCTION__, __LINE__);
                ctx->load_addr = strtoul(argv[optind++],     NULL, 16);
                //printf("%s:%d \n", __FUNCTION__, __LINE__);
                ctx->load_size = strtoul(argv[optind], NULL, 0);
                //printf("%s:%d \n", __FUNCTION__, __LINE__);
                //optind += 2;
                return 0;

            case 3: /* setpres */
                //printf("setpres: %d \n", opt);
                if (optind + 2 > argc) {
                    print_usage(argv[0]);
                    return -1;
                }
                ctx->type = CMD_SETPRES;
                ctx->n1 = atoi(argv[optind++]);
                ctx->c1 = argv[optind++][0];
                ctx->n2 = atoi(argv[optind++]);
                ctx->c2 = argv[optind][0];
                optind += 3;
                return 0;

            case 4: /* getpres */
                //printf("getpres: %d \n", opt);
                ctx->type = CMD_GETPRES;
                return 0;
            case 5:
                ssize_t ret = -1;
                if (optind >= argc) {
                    print_usage(argv[0]);
                    return -1;
                }

                ctx->type = CMD_SETBM;
                ctx->bm = strtoul(argv[optind++], NULL, 16);
                ctx->km = strtoul(argv[optind++], NULL, 16);

                ret = raw_write(ctx->dev_path, 
                                (const void *)&ctx->bm, 2, 0x72);

                if (ret < 0) {
                    fprintf(stderr, "Boot Mode write fail \n");
                    return -1;
                }
                ret = raw_write(ctx->dev_path, 
                                (const void *)&ctx->km, 2, 0x74);   
                
                if (ret < 0) {
                    fprintf(stderr, "Key Mode write fail \n");
                    return -1;
                }

                optind_pass = 1;

                //break;
            case 6:
                uint8_t bkm_buf[4] = {0, };

                ctx->type = CMD_GETBM;
                if (optind >= argc && optind_pass == 0) {
                    print_usage(argv[0]);
                    return -1;
                }

                ret = raw_read(ctx->dev_path,
                               (void *)bkm_buf, 4, 0x72);
                if (ret < 0) {
                    fprintf(stderr, "Bot Mode read fail \n");
                    return -1;
                }



                hex_dump("Boot and Key Mode", bkm_buf, 4);
                return 0;

            default:
                printf("unknown : %d \n", opt);
                print_usage(argv[0]);
                return -1;
        }
    }

    printf("end block: %d \n", opt);
    print_usage(argv[0]);
    return -1;
}

#if 0
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
#endif



