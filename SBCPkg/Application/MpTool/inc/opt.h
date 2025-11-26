#ifndef _OPT_H
#define _OPT_H

#include "log_print.h"

enum cmd_type {
    CMD_NONE = 0,
    CMD_DUMPIMG,
    CMD_LOADIMG,
    CMD_SETPRES,
    CMD_GETPRES,
    CMD_SETBM,
    CMD_GETBM
};

struct cmd_ctx {
    enum cmd_type type;
    const char *dev_path;

    /* dumpimg */
    unsigned long dump_addr;
    unsigned long dump_size;

    /* loadimg */
    const char *file;
    unsigned long load_addr;
    unsigned long load_size;

    /* setpres */
    int n1;
    char c1;
    int n2;
    char c2;

    /* boot and key mode */
    uint16_t bm;
    uint16_t km;
};

int parse_opts(int argc, char *argv[], struct cmd_ctx *ctx);
void print_usage(const char *prog);

#endif

