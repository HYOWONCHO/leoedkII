/**
 * @file sbc_tpm_nv.c
 * @brief TPM2 NV manager with NV table, CRC32, and colored hexdump.
 *
 * This module is designed for TPM2-TSS v4.x and uses SYS API only.
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <inttypes.h>

#include <tss2/tss2_sys.h>
#include <tss2/tss2_tctildr.h>
#include <tss2/tss2_rc.h>

#include "sbc_tpm.h"
#include "sbc_tpm_nv.h"

/* ============================================================
 *  Color escape codes
 * ============================================================ */
#define C_RED    "\033[31m"
#define C_GRN    "\033[32m"
#define C_YEL    "\033[33m"
#define C_BLU    "\033[34m"
#define C_CYN    "\033[36m"
#define C_RST    "\033[0m"

/* ============================================================
 *  Example NV layout
 * ============================================================ */
#define NV_KEY1     0x01500001u   /* 32 bytes */
#define NV_KEY2     0x01500002u
#define NV_KEY3     0x01500003u

#define NV_CERT1    0x01500101u   /* 512 bytes */
#define NV_CERT2    0x01500102u
#define NV_CERT3    0x01500103u

#define NV_KEY_SIZE     32u
#define NV_CERT_SIZE    512u

static SBC_NV_SLOT g_nv_table[] = {
    { NV_KEY1,  NV_KEY_SIZE,  "KEY1"  },
    { NV_KEY2,  NV_KEY_SIZE,  "KEY2"  },
    { NV_KEY3,  NV_KEY_SIZE,  "KEY3"  },
    { NV_CERT1, NV_CERT_SIZE, "CERT1" },
    { NV_CERT2, NV_CERT_SIZE, "CERT2" },
    { NV_CERT3, NV_CERT_SIZE, "CERT3" },
};

static const size_t g_nv_table_count =
    sizeof(g_nv_table) / sizeof(g_nv_table[0]);

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

        /* ASCII part */
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
 * @brief Initialize TPM context using TCTI loader.
 *
 * @param ctx       Pointer to SBC_TPM_CTX.
 * @param tcti_conf TCTI config string (e.g. "device:/dev/tpm0").
 *                  If NULL, default "device:/dev/tpmrm0" is used.
 *
 * @return SBC_OK on success, TPM2_RC_xxxx or SBC_xxxx on error.
 */
SBCStatus SBC_TpmInit(SBC_TPM_CTX *ctx, const char *tcti_conf)
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
        fprintf(stderr, C_RED "[ERROR] TctiLdr_Initialize: 0x%x (%s)\n" C_RST,
                rc, Tss2_RC_Decode(rc));
        return rc;  /* TPM error */
    }

    sys_size = Tss2_Sys_GetContextSize(0);
    ctx->sys = (TSS2_SYS_CONTEXT *)calloc(1, sys_size);
    if (!ctx->sys) {
        Tss2_TctiLdr_Finalize(&ctx->tcti);
        return SBC_MEM_ERR;
    }

    rc = Tss2_Sys_Initialize(ctx->sys, sys_size, ctx->tcti, &abi);
    if (rc != TSS2_RC_SUCCESS) {
        fprintf(stderr, C_RED "[ERROR] Sys_Initialize: 0x%x (%s)\n" C_RST,
                rc, Tss2_RC_Decode(rc));
        free(ctx->sys);
        ctx->sys = NULL;
        Tss2_TctiLdr_Finalize(&ctx->tcti);
        return rc;  /* TPM error */
    }

    return SBC_OK;
}

/**
 * @brief Finalize TPM context and free resources.
 */
void SBC_TpmFinish(SBC_TPM_CTX *ctx)
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
 *  Auth session helper
 * ============================================================ */

/**
 * @brief Initialize a password session array with empty HMAC.
 *
 * This is used for OWNER authorization when the authValue is empty.
 */
static void SBC_InitEmptyAuthSession(TSS2L_SYS_AUTH_COMMAND *sessions)
{
    if (!sessions)
        return;

    memset(sessions, 0, sizeof(*sessions));
    sessions->count = 1;
    sessions->auths[0].sessionHandle = TPM2_RS_PW;
    sessions->auths[0].hmac.size     = 0;      /* empty password */
    sessions->auths[0].sessionAttributes = 0;
}

/* ============================================================
 *  NV helpers (exist / define / undefine / ensure)
 * ============================================================ */

/**
 * @brief Check whether a TPM NV index exists.
 *
 * @param ctx    Pointer to initialized TPM SYS context.
 * @param index  NV index.
 *
 * @return
 *   1  = NV index exists
 *   0  = NV index does not exist
 *  -1  = TPM error / unexpected RC
 */
int SBC_NvExists(SBC_TPM_CTX *ctx, TPMI_RH_NV_INDEX index)
{
    if (!ctx || !ctx->sys)
        return -1;

    TPM2B_NV_PUBLIC nv_public = {0};
    TPM2B_NAME      nv_name   = {0};

    TSS2_RC rc = Tss2_Sys_NV_ReadPublic(
        ctx->sys,
        index,
        NULL,
        &nv_public,
        &nv_name,
        NULL
    );

    /* Extract base TPM_RC_xxx code using macro.
     * Tss2_RC_GetCode() does NOT exist in TPM2-TSS v4.x.
     */
    TSS2_RC rc_code =  rc & 0xFF;;

    /* Case 1: NV index exists */
    if (rc == TSS2_RC_SUCCESS)
        return 1;

    /* Case 2: NV index is not defined / invalid for current use.
     *
     * For our usage, both TPM2_RC_HANDLE and TPM2_RC_VALUE can mean
     * "this NV handle is not usable yet" → treat as "not exists" and
     * let DefineSpace create it.
     */
    if (rc_code == TPM2_RC_HANDLE || rc_code == TPM2_RC_VALUE) {
        return 0;
    }

    /* Case 3: Some TPMs return NV_DEFINED when NV index is already defined. */
    if (rc_code == TPM2_RC_NV_DEFINED) {
        fprintf(stderr,
            "[WARN] NV_ReadPublic(0x%08X) returned NV_DEFINED (0x%X). Treating as exists.\n",
            index, rc);
        return 1;
    }

    /* Case 4: Unexpected TPM error */
    fprintf(stderr,
        "[ERROR] NV_ReadPublic(0x%08X) failed: rc=0x%X (%s)\n",
        index,
        rc,
        Tss2_RC_Decode(rc)
    );

    return -1;
}

/**
 * @brief Define NV index with simple owner+auth read/write attributes.
 *
 * @return SBC_OK, TPM2_RC_xxxx, or SBC_xxxx.
 */
static SBCStatus SBC_NvDefine(SBC_TPM_CTX *ctx,
                              TPMI_RH_NV_INDEX index,
                              uint16_t size)
{
    if (!ctx || !ctx->sys)
        return SBC_ARG_ERR;

    TPM2B_AUTH auth = { .size = 0 }; /* new NV index auth (empty) */
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

    TSS2L_SYS_AUTH_COMMAND sessions;
    SBC_InitEmptyAuthSession(&sessions);

    TSS2_RC rc = Tss2_Sys_NV_DefineSpace(
        ctx->sys,
        TPM2_RH_OWNER,
        &sessions,
        &auth,
        &nv_pub,
        NULL
    );

    if (rc == TPM2_RC_NV_DEFINED) {
        printf(C_YEL "[INFO] NV index 0x%08X already defined.\n" C_RST, index);
        return rc;  /* Return TPM2_RC_NV_DEFINED */
    }

    if (rc != TSS2_RC_SUCCESS) {
        fprintf(stderr, C_RED "[ERROR] NV_DefineSpace(0x%08X): 0x%X (%s)\n" C_RST,
                index, rc, Tss2_RC_Decode(rc));
        return rc;  /* TPM error */
    }

    printf(C_GRN "[INFO] NV index 0x%08X defined (size=%u).\n" C_RST, index, size);
    return SBC_OK;
}

/**
 * @brief Undefine (delete) NV index.
 *
 * @return SBC_OK, SBC_NV_NOT_FOUND, TPM2_RC_xxxx, or SBC_xxxx.
 */
static SBCStatus SBC_NvUndefine(SBC_TPM_CTX *ctx, TPMI_RH_NV_INDEX index)
{
    if (!ctx || !ctx->sys)
        return SBC_ARG_ERR;

    TSS2L_SYS_AUTH_COMMAND sessions;
    SBC_InitEmptyAuthSession(&sessions);

    TSS2_RC rc = Tss2_Sys_NV_UndefineSpace(
        ctx->sys,
        TPM2_RH_OWNER,
        index,
        &sessions,
        NULL
    );

    if (rc == TPM2_RC_HANDLE) {
        printf(C_YEL "[INFO] NV index 0x%08X does not exist.\n" C_RST, index);
        return SBC_NV_NOT_FOUND;
    }

    if (rc != TSS2_RC_SUCCESS) {
        fprintf(stderr, C_RED "[ERROR] NV_UndefineSpace(0x%08X): 0x%X (%s)\n" C_RST,
                index, rc, Tss2_RC_Decode(rc));
        return rc;  /* TPM error */
    }

    printf(C_GRN "[INFO] NV index 0x%08X undefined.\n" C_RST, index);
    return SBC_OK;
}

/**
 * @brief Ensure NV index is defined with expected size.
 *
 * If the NV index does not exist, this function will define it.
 */
SBCStatus SBC_NvEnsureDefined(SBC_TPM_CTX *ctx,
                              TPMI_RH_NV_INDEX index,
                              uint16_t size)
{
    int exists = SBC_NvExists(ctx, index);
    if (exists < 0)
        return SBC_FAIL;

    if (exists == 1) {
        /* Already defined, do not redefine */
        return SBC_OK;
    }

    /* exists == 0 → not defined, create new NV space */
    return SBC_NvDefine(ctx, index, size);
}

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
 *
 * @return SBC_OK, TPM2_RC_xxxx, or SBC_xxxx.
 */
SBCStatus SBC_NvWriteChecked(SBC_TPM_CTX *ctx,
                             const SBC_NV_SLOT *slot,
                             const uint8_t *data,
                             uint16_t size,
                             uint32_t expected_crc)
{
    if (!ctx || !ctx->sys || !slot || !data)
        return SBC_ARG_ERR;

    if (size != slot->size) {
        fprintf(stderr, C_RED "[ERROR] NV size mismatch: slot=%u, input=%u\n" C_RST,
                slot->size, size);
        return SBC_SIZE_ERR;
    }

    /* Compute CRC */
    uint32_t crc = crc32_calc(data, size);
    printf(C_CYN "[INFO] CRC32(%s) = 0x%08X\n" C_RST, slot->name, crc);

    if (expected_crc != 0 && crc != expected_crc) {
        fprintf(stderr,
                C_RED "[ERROR] CRC mismatch: expected=0x%08X, calc=0x%08X\n" C_RST,
                expected_crc, crc);
        return SBC_CRC_ERR;
    }

    /* Ensure NV index exists */
    SBCStatus st = SBC_NvEnsureDefined(ctx, slot->index, slot->size);
    if (st != SBC_OK) {
        return st;  /* Could be TPM RC or SBC_xxxx */
    }

    TPM2B_MAX_NV_BUFFER nv_write = {0};

    if (size > sizeof(nv_write.buffer))
        return SBC_SIZE_ERR;

    nv_write.size = size;
    memcpy(nv_write.buffer, data, size);

    TSS2L_SYS_AUTH_COMMAND sessions;
    SBC_InitEmptyAuthSession(&sessions);

    /* Use OWNER hierarchy as auth handle (OWNERWRITE attribute is set). */
    TSS2_RC rc = Tss2_Sys_NV_Write(
        ctx->sys,
        TPM2_RH_OWNER,          /* authHandle */
        slot->index,            /* nvIndex   */
        &sessions,              /* cmdAuths  */
        &nv_write,
        0,
        NULL
    );

    if (rc != TSS2_RC_SUCCESS) {
        fprintf(stderr, C_RED "[ERROR] NV_Write(%s, 0x%08X): 0x%X (%s)\n" C_RST,
                slot->name, slot->index, rc, Tss2_RC_Decode(rc));
        return rc;  /* TPM error */
    }

    printf(C_GRN "[INFO] NV_Write %s (0x%08X) size=%u OK\n" C_RST,
           slot->name, slot->index, size);
    return SBC_OK;
}

/**
 * @brief Read NV data and print colored hexdump.
 *
 * @return SBC_OK, TPM2_RC_xxxx, or SBC_xxxx.
 */
SBCStatus SBC_NvReadHexdump(SBC_TPM_CTX *ctx,
                            const SBC_NV_SLOT *slot)
{
    if (!ctx || !ctx->sys || !slot)
        return SBC_ARG_ERR;

    int exists = SBC_NvExists(ctx, slot->index);
    if (exists <= 0) {
        fprintf(stderr, C_RED "[ERROR] NV index 0x%08X does not exist.\n" C_RST,
                slot->index);
        return SBC_NV_NOT_FOUND;
    }

    TPM2B_MAX_NV_BUFFER nv_read = {0};

    TSS2L_SYS_AUTH_COMMAND sessions;
    SBC_InitEmptyAuthSession(&sessions);

    /* Use OWNER hierarchy as auth handle (OWNERREAD attribute is set). */
    TSS2_RC rc = Tss2_Sys_NV_Read(
        ctx->sys,
        TPM2_RH_OWNER,          /* authHandle */
        slot->index,            /* nvIndex    */
        &sessions,              /* cmdAuths   */
        slot->size,
        0,
        &nv_read,
        NULL
    );

    if (rc != TSS2_RC_SUCCESS) {
        fprintf(stderr, C_RED "[ERROR] NV_Read(%s, 0x%08X): 0x%X (%s)\n" C_RST,
                slot->name, slot->index, rc, Tss2_RC_Decode(rc));
        return rc;  /* TPM error */
    }

    printf(C_BLU "\n[INFO] NV_Read %s (0x%08X) size=%u\n" C_RST,
           slot->name, slot->index, nv_read.size);
    hexdump_color(nv_read.buffer, nv_read.size);
    return SBC_OK;
}

/* ============================================================
 *  Example vectors for testing
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
 *  Test entry
 * ============================================================ */

/**
 * @brief Simple test routine for NV manager.
 *
 * This function:
 *   - Initializes TPM
 *   - Writes KEY1 and CERT1 to NV with CRC check
 *   - Reads KEY1 and CERT1 and prints hexdump
 */
int sbc_nv_test_main(void)
{
    SBC_TPM_CTX ctx;
    SBCStatus st;

    fill_example_vectors();

    /* You can switch between /dev/tpm0 and /dev/tpmrm0 here. */
    st = SBC_TpmInit(&ctx, "device:/dev/tpm0");
    if (st != SBC_OK) {
        if (SBC_IS_TPM_RC(st)) {
            fprintf(stderr, C_RED "[FATAL] SBC_TpmInit failed: 0x%08X (%s)\n" C_RST,
                    st, Tss2_RC_Decode(st));
        } else {
            fprintf(stderr, C_RED "[FATAL] SBC_TpmInit failed: 0x%08X (SBC internal)\n" C_RST,
                    st);
        }
        return 1;
    }

    const SBC_NV_SLOT *slot_key1  = SBC_NvFindSlotByName("KEY1");
    const SBC_NV_SLOT *slot_cert1 = SBC_NvFindSlotByName("CERT1");

    if (!slot_key1 || !slot_cert1) {
        fprintf(stderr, C_RED "[FATAL] NV slot not found in table\n" C_RST);
        SBC_TpmFinish(&ctx);
        return 1;
    }

    /* Write KEY1 with CRC check (expected_crc = 0 to skip compare) */
    st = SBC_NvWriteChecked(&ctx, slot_key1, g_key1, sizeof(g_key1), 0);
    if (st != SBC_OK) {
        if (SBC_IS_TPM_RC(st)) {
            fprintf(stderr, C_RED "[ERROR] SBC_NvWriteChecked(KEY1) TPM failed: 0x%08X (%s)\n" C_RST,
                    st, Tss2_RC_Decode(st));
        } else {
            fprintf(stderr, C_RED "[ERROR] SBC_NvWriteChecked(KEY1) failed: 0x%08X\n" C_RST, st);
        }
        SBC_TpmFinish(&ctx);
        return 1;
    }

    /* Read KEY1 */
    st = SBC_NvReadHexdump(&ctx, slot_key1);
    if (st != SBC_OK) {
        if (SBC_IS_TPM_RC(st)) {
            fprintf(stderr, C_RED "[ERROR] SBC_NvReadHexdump(KEY1) TPM failed: 0x%08X (%s)\n" C_RST,
                    st, Tss2_RC_Decode(st));
        } else {
            fprintf(stderr, C_RED "[ERROR] SBC_NvReadHexdump(KEY1) failed: 0x%08X\n" C_RST, st);
        }
        SBC_TpmFinish(&ctx);
        return 1;
    }

    /* Write CERT1 */
    st = SBC_NvWriteChecked(&ctx, slot_cert1, g_cert1, sizeof(g_cert1), 0);
    if (st != SBC_OK) {
        if (SBC_IS_TPM_RC(st)) {
            fprintf(stderr, C_RED "[ERROR] SBC_NvWriteChecked(CERT1) TPM failed: 0x%08X (%s)\n" C_RST,
                    st, Tss2_RC_Decode(st));
        } else {
            fprintf(stderr, C_RED "[ERROR] SBC_NvWriteChecked(CERT1) failed: 0x%08X\n" C_RST, st);
        }
        SBC_TpmFinish(&ctx);
        return 1;
    }

    /* Read CERT1 */
    st = SBC_NvReadHexdump(&ctx, slot_cert1);
    if (st != SBC_OK) {
        if (SBC_IS_TPM_RC(st)) {
            fprintf(stderr, C_RED "[ERROR] SBC_NvReadHexdump(CERT1) TPM failed: 0x%08X (%s)\n" C_RST,
                    st, Tss2_RC_Decode(st));
        } else {
            fprintf(stderr, C_RED "[ERROR] SBC_NvReadHexdump(CERT1) failed: 0x%08X\n" C_RST, st);
        }
        SBC_TpmFinish(&ctx);
        return 1;
    }

    /* Optional: test undefine */
    // st = SBC_NvUndefine(&ctx, slot_cert1->index);

    SBC_TpmFinish(&ctx);
    return 0;
}

