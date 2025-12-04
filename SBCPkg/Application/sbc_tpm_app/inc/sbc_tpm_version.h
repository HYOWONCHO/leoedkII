#ifndef TPM_VERSION_H
#define TPM_VERSION_H

#include <tss2/tss2_esys.h>

#define TPM_DEVICE "/dev/tpm0"

int tpm_print_random(void);
int tpm_print_version(void);

#endif

