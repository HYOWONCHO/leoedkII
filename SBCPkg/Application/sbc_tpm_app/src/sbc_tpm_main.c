#include <stdio.h>
#include <stdlib.h>
#include <errno.h>
#include <string.h>
#include <stdint.h>

#include "sbc_tpm_version.h"


int main(int argc, char *argv[])
{
    printf("=== TPM Example Start ===\n");

    tpm_print_version();

    if (tpm_print_random() != 0) {
        printf("TPM Random read failed!\n");
        return -1;
    }

    printf("=== Example Done ===\n");
    return 0;

}
