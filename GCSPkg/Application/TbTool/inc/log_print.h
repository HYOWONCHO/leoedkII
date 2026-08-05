#ifndef _LOG_PRINT_H_ 
#define _LOG_PRINT_H_

#include <stdio.h>
#include <stdint.h>
#include <stddef.h>
#include <sys/types.h>

#include "opt.h"

#define RESET   "\033[0m"
#define RED     "\033[31m"
#define GREEN   "\033[32m"
#define YELLOW  "\033[33m"
#define BLUE    "\033[34m"
#define MAGENTA "\033[35m"
#define CYAN    "\033[36m"
#define WHITE   "\033[37m"

/**
 * hex_dump - print hex dump (16-byte aligned, with ASCII)
 * @buf:   pointer to input buffer
 * @len:   buffer length
 *
 * This prints the buffer in a classic "hexdump -C" style.
 */



static inline void hex_dump(const char *title, const void *buf, size_t len)
{
    const uint8_t *data = (const uint8_t *)buf;
    size_t i, j;

    if (title)
        printf(GREEN "%s (len: %zu):\n" RESET, title, len);

    /* print column index header */
    printf("          ");
    for (j = 0; j < 16; j++) {
        printf(YELLOW "%02X ", (unsigned int)j);
        if (j == 7)
            printf(" ");
    }
    printf("\n");

    /* separator line */
    printf("----------------------------------------------------------------------\n" RESET);

    for (i = 0; i < len; i += 16) {

        /* offset */
        //printf("%08zx  ", i);
        printf("%08zx  ", i);

        /* hex bytes */
        for (j = 0; j < 16; j++) {
            if (i + j < len)
                printf("%02x ", data[i + j]);
            else
                printf("   ");

            if (j == 7)
                printf(" ");
        }

        /* ASCII area */
        printf(" |");

        for (j = 0; j < 16 && (i + j) < len; j++) {
            unsigned char c = data[i + j];
            printf("%c", (c >= 0x20 && c <= 0x7e) ? c : '.');
        }

        printf("|\n");
    }
}

#endif /* HEX_DUMP_H */

