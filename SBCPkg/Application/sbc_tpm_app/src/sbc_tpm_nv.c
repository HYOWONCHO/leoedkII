/**
 * @file sbc_tpm_nv_manager.c
 * @brief Simple TPM2 NV manager with NV table, CRC check and colored hexdump.
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <inttypes.h>

#include <tss2/tss2_sys.h>
#include <tss2/tss2_tctildr.h>

/* ============================================================
 *  Color
 * ============================================================ */
#define C_RED    "\033[31m"
#define C_GRN    "\033[32m"
#define C_YEL    "\033[33m"
#define C_BLU    "\033[34m"
#define C_CYN    "\033[36m"
#define C_RST    "\033[0m"

/* ============================================================
 *  SBCStatus
 * ============================================================ */
typedef enum {
    SBC_OK = 0,
    SBC_FAIL,
    SBC_TPM_ERR,
    SBC_ARG_ERR,
    SBC_MEM_ERR,
    SBC_NV_NOT_FOUND,
    SBC_NV_ALREADY_DEFINED,
    SBC_NV_SIZE_MISMATCH,
    SBC_CRC_MISMATCH
} SBCStatus;

/* ============================================================
 *  TPM context
 * ============================================================ */
typedef struct {
    TSS2_TCTI_CONTEXT *tcti;
    TSS2_SYS_CONTEXT  *sys;
} SBC_TPM_CTX;

/* ============================================================
 *  NV Slot table
 * ============================================================ */
typedef struct {
    TPMI_RH_NV_INDEX index;
    UINT16           size;
    const char      *name;   /* logical name (e.g. "KEY1", "CERT1") */
} SBC_NV_SLOT;

/* Example NV layout */
#define NV_KEY1     0x01500001   /* 32 bytes */
#define NV_KEY2     0x01500002
#define NV_KEY3     0x01500003

#define NV_CERT1    0x01500101   /* 512 bytes */
#define NV_CERT2    0x01500102
#define NV_CERT3    0x01500103

#define NV_KEY_SIZE     32
#define NV_CERT_SIZE    512

static SBC_NV_SLOT g_nv_table[] = {
    { NV_KEY1,  NV_KEY_SIZE,  "KEY1"  },
    { NV_KEY2,  NV_KEY_SIZE,  "KEY2"  },
    { NV_KEY3,  NV_KEY_SIZE,  "KEY3"  },
    { NV_CERT1, NV_CERT_SIZE, "CERT1" },
    { NV_CERT2, NV_CERT_SIZE, "CERT2" },
    { NV_CERT3, NV_CERT_SIZE, "CERT3" },
};

static const size_t g_nv_table_count = sizeof(g_nv_table) / sizeof(g_nv_table[0]);

/* ============================================================
 *  CRC32
 * ============================================================ */

/**
 * @brief Compute CRC32 of a buffer.
 */
static uint32_t crc32_calc(const uint8_t *buf, size_t len)
{
    uint32_t crc = 0xFFFFFFFFu;

    for (size_t i = 0; i < len; ++i) {
        uint32_t byte = buf[i];
        crc ^= byte;
        for (int j = 0; j < 8; ++j) {
            uint32_t mask = -(crc & 1u);
            crc = (crc >> 1) ^ (0xEDB88320u & mask);
        }
    }
    return ~crc;
}

/* ============================================================
 *  Colored hexdump
 * ============================================================ */

/**
 * @brief Print buffer in colored hexdump format.
 */
static void hexdump_color(const uint8_t *data, size_t size)
{
    for (size_t i = 0; i < size; i += 16) {
        /* offset */
        printf(C_CYN "%04zx  " C_RST, i);

        /* hex part */
        for (size_t j = 0; j < 16; j++) {
            if (i + j < size)
                printf(C_GRN "%02x " C_RST, data[i + j]);
            else
                printf("   ");
        }

        printf(" |");

        /* ascii part */
        for (size_t j = 0; j < 16; j++) {
            if (i + j < size) {
                uint8_t c = data[i + j];
                if (c >= 32 && c <= 126)
                    printf(C_YEL "%c" C_RST, c);
                else
                    printf(".");
            } else {
                printf(" ");
            }
        }

        printf("|\n");
    }
}

/* ============================================================
 *  TPM init / finish
 * ============================================================ */

/**
 * @brief Initialize TPM context using tcti loader.
 *
 * @param ctx       Context pointer.
 * @param tcti_conf TCTI string, e.g. "device:/dev/tpm0". If NULL, default used.
 */
static SBCStatus SBC_TpmInit(SBC_TPM_CTX *ctx, const char *tcti_conf)
{
    if (!ctx)
        return SBC_ARG_ERR;

    memset(ctx, 0, sizeof(*ctx));

    if (!tcti_conf)
        tcti_conf = "device:/dev/tpmrm0";

    TSS2_RC rc;
    TSS2_ABI_VERSION abi = TSS2_ABI_VERSION_CURRENT;
    size_t sys_size;

    rc = Tss2_TctiLdr_Initialize(tcti_conf, &ctx->tcti);
    if (rc != TSS2_RC_SUCCESS) {
        fprintf(stderr, C_RED "[ERROR] TctiLdr_Initialize: 0x%x\n" C_RST, rc);
        return SBC_TPM_ERR;
    }

    sys_size = Tss2_Sys_GetContextSize(0);
    ctx->sys = (TSS2_SYS_CONTEXT *)calloc(1, sys_size);
    if (!ctx->sys) {
        Tss2_TctiLdr_Finalize(&ctx->tcti);
        return SBC_MEM_ERR;
    }

    rc = Tss2_Sys_Initialize(ctx->sys, sys_size, ctx->tcti, &abi);
    if (rc != TSS2_RC_SUCCESS) {
        fprintf(stderr, C_RED "[ERROR] Sys_Initialize: 0x%x\n" C_RST, rc);
        free(ctx->sys);
        ctx->sys = NULL;
        Tss2_TctiLdr_Finalize(&ctx->tcti);
        return SBC_TPM_ERR;
    }

    return SBC_OK;
}

/**
 * @brief Finalize TPM context.
 */
static void SBC_TpmFinish(SBC_TPM_CTX *ctx)
{
    if (!ctx)
        return;

    if (ctx->sys) {
        Tss2_Sys_Finalize(ctx->sys);
        free(ctx->sys);
        ctx->sys = NULL;
    }
    if (ctx->tcti) {
        Tss2_TctiLdr_Finalize(&ctx->tcti);
        ctx->tcti = NULL;
    }
}

/* ============================================================
 *  NV helpers (exist / define / undefine)
 * ============================================================ */

/**
 * @brief Check if NV index exists.
 *
 * @return 1 = exists, 0 = not exist, <0 = error.
 */
int SBC_NvExists(SBC_TPM_CTX *ctx, TPMI_RH_NV_INDEX index)
{
    if (!ctx || !ctx->sys)
        return -1;

    TPM2B_NV_PUBLIC nv_public = {0};
    TPM2B_NAME nv_name = {0};
    TSS2_RC rc = Tss2_Sys_NV_ReadPublic(
        ctx->sys,
        index,
        NULL,
        &nv_public,
        &nv_name,
        NULL
    );

    TSS2_RC base_rc = rc & 0xFFFF;  /* strip layer bits */

    if (rc == TSS2_RC_SUCCESS) {
        /* NV index exists and is readable */
        return 1;
    }

    if (base_rc == TPM2_RC_HANDLE) {
        /* NV index not defined */
        return 0;
    }

    if (base_rc == TPM2_RC_NV_DEFINED) {
        /* NV index is already defined (treat as exists) */
        fprintf(stderr,
            "[WARN] NV_ReadPublic(0x%08x) returned NV_DEFINED (0x%x), "
            "treating as 'exists'.\n",
            index, rc);
        return 1;
    }

    fprintf(stderr,
        "[ERROR] NV_ReadPublic(0x%08x) failed with rc=0x%x\n",
        index, rc);
    return -1;
}



/**
 * @brief Define NV index with simple owner+auth read/write attributes.
 */
static SBCStatus SBC_NvDefine(SBC_TPM_CTX *ctx,
                              TPMI_RH_NV_INDEX index,
                              UINT16 size)
{
    if (!ctx || !ctx->sys)
        return SBC_ARG_ERR;

    TPM2B_AUTH auth = { .size = 0 }; /* empty auth */
    TPM2B_NV_PUBLIC nv_pub = {0};
    nv_pub.size = sizeof(TPMS_NV_PUBLIC);
    nv_pub.nvPublic.nvIndex = index;
    nv_pub.nvPublic.nameAlg = TPM2_ALG_SHA256;
    nv_pub.nvPublic.attributes =
          TPMA_NV_AUTHREAD
        | TPMA_NV_AUTHWRITE
        | TPMA_NV_OWNERREAD
        | TPMA_NV_OWNERWRITE;
    nv_pub.nvPublic.dataSize = size;

    TSS2_RC rc = Tss2_Sys_NV_DefineSpace(
        ctx->sys,
        TPM2_RH_OWNER,
        NULL,
        &auth,
        &nv_pub,
        NULL
    );

    if (rc == TPM2_RC_NV_DEFINED) {
        printf(C_YEL "[INFO] NV index 0x%08x already defined.\n" C_RST, index);
        return SBC_NV_ALREADY_DEFINED;
    }

    if (rc != TSS2_RC_SUCCESS) {
        fprintf(stderr, C_RED "[ERROR] NV_DefineSpace(0x%08x): 0x%x\n" C_RST, index, rc);
        return SBC_TPM_ERR;
    }

    printf(C_GRN "[INFO] NV index 0x%08x defined (size=%u).\n" C_RST, index, size);
    return SBC_OK;
}

/**
 * @brief Undefine (delete) NV index.
 */
static SBCStatus SBC_NvUndefine(SBC_TPM_CTX *ctx, TPMI_RH_NV_INDEX index)
{
    if (!ctx || !ctx->sys)
        return SBC_ARG_ERR;

    TSS2_RC rc = Tss2_Sys_NV_UndefineSpace(
        ctx->sys,
        TPM2_RH_OWNER,
        index,
        NULL,
        NULL
    );

    if (rc == TPM2_RC_HANDLE) {
        printf(C_YEL "[INFO] NV index 0x%08x does not exist.\n" C_RST, index);
        return SBC_NV_NOT_FOUND;
    }

    if (rc != TSS2_RC_SUCCESS) {
        fprintf(stderr, C_RED "[ERROR] NV_UndefineSpace(0x%08x): 0x%x\n" C_RST, index, rc);
        return SBC_TPM_ERR;
    }

    printf(C_GRN "[INFO] NV index 0x%08x undefined.\n" C_RST, index);
    return SBC_OK;
}

/**
 * @brief Ensure NV index is defined with expected size.
 */
#if 0
static SBCStatus SBC_NvEnsureDefined(SBC_TPM_CTX *ctx,
                                     TPMI_RH_NV_INDEX index,
                                     UINT16 size)
{
    int exists = SBC_NvExists(ctx, index);
    if (exists < 0)
        return SBC_TPM_ERR;

    if (exists == 1) {
        printf(C_GRN "[INFO] NV index 0x%08x exists.\n" C_RST, index);
        return SBC_OK;
    }

    printf(C_YEL "[INFO] NV index 0x%08x not found. Defining...\n" C_RST, index);
    return SBC_NvDefine(ctx, index, size);
}
#else
SBCStatus SBC_NvEnsureDefined(SBC_TPM_CTX *ctx,
                              TPMI_RH_NV_INDEX index,
                              uint16_t size)
{
    int exists = SBC_NvExists(ctx, index);
    if (exists < 0)
        return SBC_TPM_ERR;

    if (exists == 1) {
        /* Already defined, do not redefine */
        return SBC_OK;
    }

    /* exists == 0 → not defined, create new NV space */
    return SBC_NvDefine(ctx, index, size);
}


#endif

/* ============================================================
 *  NV read / write with CRC check
 * ============================================================ */

/**
 * @brief Find NV slot from table by logical name.
 */
static const SBC_NV_SLOT* SBC_NvFindSlotByName(const char *name)
{
    if (!name)
        return NULL;

    for (size_t i = 0; i < g_nv_table_count; ++i) {
        if (strcmp(g_nv_table[i].name, name) == 0)
            return &g_nv_table[i];
    }
    return NULL;
}

/**
 * @brief Write data into NV after CRC check.
 *
 * @param expected_crc If non-zero, compare with computed CRC and fail on mismatch.
 */
static SBCStatus SBC_NvWriteChecked(SBC_TPM_CTX *ctx,
                                    const SBC_NV_SLOT *slot,
                                    const uint8_t *data,
                                    UINT16 size,
                                    uint32_t expected_crc)
{
    if (!ctx || !ctx->sys || !slot || !data)
        return SBC_ARG_ERR;

    if (size != slot->size) {
        fprintf(stderr, C_RED "[ERROR] NV size mismatch: slot=%u, input=%u\n" C_RST,
                slot->size, size);
        return SBC_NV_SIZE_MISMATCH;
    }

    /* Compute CRC */
    uint32_t crc = crc32_calc(data, size);
    printf(C_CYN "[INFO] CRC32(%s) = 0x%08x\n" C_RST, slot->name, crc);

    if (expected_crc != 0 && crc != expected_crc) {
        fprintf(stderr,
                C_RED "[ERROR] CRC mismatch: expected=0x%08x, calc=0x%08x\n" C_RST,
                expected_crc, crc);
        return SBC_CRC_MISMATCH;
    }

    /* Ensure NV index exists */
    SBCStatus st = SBC_NvEnsureDefined(ctx, slot->index, slot->size);
    if (st != SBC_OK && st != SBC_NV_ALREADY_DEFINED)
        return st;

    TPM2B_MAX_NV_BUFFER nv_write = {0};
    TPM2B_AUTH auth = { .size = 0 }; /* empty auth */

    if (size > sizeof(nv_write.buffer))
        return SBC_NV_SIZE_MISMATCH;

    nv_write.size = size;
    memcpy(nv_write.buffer, data, size);

    TSS2_RC rc = Tss2_Sys_NV_Write(
        ctx->sys,
        slot->index,
        slot->index,
        &auth,
        &nv_write,
        0,
        NULL
    );

    if (rc != TSS2_RC_SUCCESS) {
        fprintf(stderr, C_RED "[ERROR] NV_Write(0x%08x): 0x%x\n" C_RST,
                slot->index, rc);
        return SBC_TPM_ERR;
    }

    printf(C_GRN "[INFO] NV_Write %s (0x%08x) size=%u OK\n" C_RST,
           slot->name, slot->index, size);
    return SBC_OK;
}

/**
 * @brief Read NV data and print colored hexdump.
 */
static SBCStatus SBC_NvReadHexdump(SBC_TPM_CTX *ctx,
                                   const SBC_NV_SLOT *slot)
{
    if (!ctx || !ctx->sys || !slot)
        return SBC_ARG_ERR;

    int exists = SBC_NvExists(ctx, slot->index);
    if (exists <= 0) {
        fprintf(stderr, C_RED "[ERROR] NV index 0x%08x does not exist.\n" C_RST,
                slot->index);
        return SBC_NV_NOT_FOUND;
    }

    TPM2B_MAX_NV_BUFFER nv_read = {0};
    TPM2B_AUTH auth = { .size = 0 };

    TSS2_RC rc = Tss2_Sys_NV_Read(
        ctx->sys,
        slot->index,
        slot->index,
        &auth,
        slot->size,
        0,
        &nv_read,
        NULL
    );

    if (rc != TSS2_RC_SUCCESS) {
        fprintf(stderr, C_RED "[ERROR] NV_Read(0x%08x): 0x%x\n" C_RST,
                slot->index, rc);
        return SBC_TPM_ERR;
    }

    printf(C_BLU "\n[INFO] NV_Read %s (0x%08x) size=%u\n" C_RST,
           slot->name, slot->index, nv_read.size);
    hexdump_color(nv_read.buffer, nv_read.size);
    return SBC_OK;
}
/* ============================================================
 *  Example vectors
 * ============================================================ */

static uint8_t g_key1[NV_KEY_SIZE] = {
    0x10,0x11,0x12,0x13,0x14,0x15,0x16,0x17,
    0x20,0x21,0x22,0x23,0x24,0x25,0x26,0x27,
    0x30,0x31,0x32,0x33,0x34,0x35,0x36,0x37,
    0x40,0x41,0x42,0x43,0x44,0x45,0x46,0x47
};

static uint8_t g_cert1[NV_CERT_SIZE];

static void fill_example_vectors(void)
{
    memset(g_cert1, 0x11, sizeof(g_cert1));
}

/* ============================================================
 *  main()
 * ============================================================ */

int sbc_nv_test_main(void)
{
    SBC_TPM_CTX ctx;
    SBCStatus st;

    fill_example_vectors();

    st = SBC_TpmInit(&ctx, "device:/dev/tpm0");
    if (st != SBC_OK) {
        fprintf(stderr, C_RED "[FATAL] SBC_TpmInit failed\n" C_RST);
        return 1;
    }

    /* KEY1 write + read */
    const SBC_NV_SLOT *slot_key1 = SBC_NvFindSlotByName("KEY1");
    const SBC_NV_SLOT *slot_cert1 = SBC_NvFindSlotByName("CERT1");

    if (!slot_key1 || !slot_cert1) {
        fprintf(stderr, C_RED "[FATAL] NV slot not found in table\n" C_RST);
        SBC_TpmFinish(&ctx);
        return 1;
    }

    /* Write key1 with CRC check (expected_crc = 0 to skip compare) */
    st = SBC_NvWriteChecked(&ctx, slot_key1, g_key1, sizeof(g_key1), 0);
    if (st != SBC_OK) {
        fprintf(stderr, C_RED "[ERROR] SBC_NvWriteChecked(KEY1) failed (%d)\n" C_RST, st);
        SBC_TpmFinish(&ctx);
        return 1;
    }

    /* Read key1 */
    st = SBC_NvReadHexdump(&ctx, slot_key1);
    if (st != SBC_OK) {
        fprintf(stderr, C_RED "[ERROR] SBC_NvReadHexdump(KEY1) failed (%d)\n" C_RST, st);
        SBC_TpmFinish(&ctx);
        return 1;
    }

    /* Write cert1 */
    st = SBC_NvWriteChecked(&ctx, slot_cert1, g_cert1, sizeof(g_cert1), 0);
    if (st != SBC_OK) {
        fprintf(stderr, C_RED "[ERROR] SBC_NvWriteChecked(CERT1) failed (%d)\n" C_RST, st);
        SBC_TpmFinish(&ctx);
        return 1;
    }

    /* Read cert1 */
    st = SBC_NvReadHexdump(&ctx, slot_cert1);
    if (st != SBC_OK) {
        fprintf(stderr, C_RED "[ERROR] SBC_NvReadHexdump(CERT1) failed (%d)\n" C_RST, st);
        SBC_TpmFinish(&ctx);
        return 1;
    }

    /* 예: CERT1 NV 삭제 테스트 */
    // st = SBC_NvUndefine(&ctx, slot_cert1->index);

    SBC_TpmFinish(&ctx);
    return 0;
}

