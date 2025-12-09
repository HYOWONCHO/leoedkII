/**
 * @file sbc_tpm_nv.c
 * @brief TPM2 NV manager with NV table, CRC32, colored hexdump, file I/O, and TPM random.
 *
 * This module is designed for TPM2-TSS v4.x and uses SYS API only.
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <inttypes.h>
#include <errno.h>
#include <stdbool.h>

#include <tss2/tss2_sys.h>
#include <tss2/tss2_tctildr.h>
#include <tss2/tss2_rc.h>

#include <time.h>   /* for srand/time */


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


/**
 * @brief Load certificate file, then store only random-length bytes.
 *
 * Random length range:
 *      64 ~ NV_CERT_SIZE
 *
 * Behavior:
 *   - If file is smaller than random length → pad with 0x00
 *   - If file is larger than random length → truncate
 *   - Output buffer is ALWAYS NV_CERT_SIZE bytes (padded with 0x00)
 *
 * @return 1 = success, 0 = fail
 */
static int SBC_LoadCertRandomSize(
    const char *path,
    uint8_t *out_buf,
    size_t *used_len
)
{
    /* Choose random size between 64 and NV_CERT_SIZE */
    size_t rand_size = (size_t)(rand() % (NV_CERT_SIZE - 64 + 1)) + 64;

    uint8_t temp[4096];

    FILE *fp = fopen(path, "rb");
    if (!fp) {
        fprintf(stderr, C_RED "[ERROR] Cannot open cert file: %s\n" C_RST, path);
        return 0;
    }

    size_t read_size = fread(temp, 1, sizeof(temp), fp);
    fclose(fp);

    if (read_size == 0) {
        fprintf(stderr, C_RED "[ERROR] Empty cert file: %s\n" C_RST, path);
        return 0;
    }

    /* Determine how many bytes to copy into NV buffer */
    size_t copy = (read_size > rand_size ? rand_size : read_size);

    /* Copy certificate bytes */
    memcpy(out_buf, temp, copy);

    /* If file is shorter than chosen random length → pad the rest */
    if (copy < rand_size) {
        memset(out_buf + copy, 0x00, rand_size - copy);
    }

    /* Fill the remaining NV slot with zeros up to NV_CERT_SIZE */
    if (rand_size < NV_CERT_SIZE) {
        memset(out_buf + rand_size, 0x00, NV_CERT_SIZE - rand_size);
    }

    *used_len = rand_size;

    printf(C_GRN "[INFO] Loaded cert %s (file=%zu, used=%zu, padded=%zu)\n" C_RST,
           path, read_size, rand_size, NV_CERT_SIZE - rand_size);

    return 1;
}


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
 *  Hexdump
 * ============================================================ */

/**
 * @brief Print buffer in professional hex view format with header.
 *
 * Example:
 *        00 01 02 03 04 05 06 07 08 09 0A 0B 0C 0D 0E 0F
 *        ------------------------------------------------
 * 0000 | 48 65 6C 6C 6F 20 ... |Hello...|
 */
static void hexdump_color(const uint8_t *data, size_t size)
{
    const size_t bytes_per_line = 16;

    /* Header: column indexes */
    printf("      ");
    for (size_t i = 0; i < bytes_per_line; i++)
        printf("%02zx ", i);
    printf("\n");

    /* Header: separator line */
    printf("      ");
    for (size_t i = 0; i < bytes_per_line; i++)
        printf("---");
    printf("\n");

    /* Hexdump contents */
    for (size_t offset = 0; offset < size; offset += bytes_per_line) {

        /* Print offset */
        printf(C_CYN "%04zx" C_RST " | ", offset);

        /* Hex region */
        for (size_t i = 0; i < bytes_per_line; i++) {
            size_t idx = offset + i;
            if (idx < size)
                printf(C_GRN "%02x " C_RST, data[idx]);
            else
                printf("   ");
        }

        printf("| ");

        /* ASCII region */
        for (size_t i = 0; i < bytes_per_line; i++) {
            size_t idx = offset + i;
            if (idx < size) {
                uint8_t c = data[idx];
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
    sessions->auths[0].sessionHandle    = TPM2_RS_PW;
    sessions->auths[0].hmac.size        = 0;      /* empty password */
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

    /* Extract base TPM_RC_xxx code (low 8 bits).
     * Tss2_RC_GetCode() / TSS2_RC_GET_CODE() are not available in TPM2-TSS v4.
     */
    TSS2_RC rc_code = rc & 0xFF;

    /* Case 1: NV index exists */
    if (rc == TSS2_RC_SUCCESS)
        return 1;

    /* Case 2: NV index is not defined / invalid for current use. */
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
            C_RED "[ERROR] NV_ReadPublic(0x%08X) failed: rc=0x%X (%s)\n" C_RST,
            index,
            rc,
            Tss2_RC_Decode(rc));

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

/* ============================================================
 *  NV generic buffer read
 * ============================================================ */

/**
 * @brief Read NV data into caller-provided buffer.
 *
 * @param ctx           TPM context.
 * @param slot          NV slot descriptor.
 * @param out_buf       Output buffer.
 * @param out_buf_size  Output buffer size in bytes.
 * @param out_read_size Optional; actual bytes read (can be NULL).
 *
 * @return SBC_OK, TPM2_RC_xxxx, or SBC_xxxx.
 */
SBCStatus SBC_NvReadBuffer(SBC_TPM_CTX *ctx,
                           const SBC_NV_SLOT *slot,
                           uint8_t *out_buf,
                           uint16_t out_buf_size,
                           uint16_t *out_read_size)
{
    if (!ctx || !ctx->sys || !slot || !out_buf)
        return SBC_ARG_ERR;

    if (out_buf_size < slot->size) {
        fprintf(stderr, C_RED "[ERROR] Output buffer too small: needed=%u, got=%u\n" C_RST,
                slot->size, out_buf_size);
        return SBC_SIZE_ERR;
    }

    int exists = SBC_NvExists(ctx, slot->index);
    if (exists <= 0) {
        fprintf(stderr, C_RED "[ERROR] NV index 0x%08X does not exist.\n" C_RST,
                slot->index);
        return SBC_NV_NOT_FOUND;
    }

    TPM2B_MAX_NV_BUFFER nv_read = {0};
    TSS2L_SYS_AUTH_COMMAND sessions;
    SBC_InitEmptyAuthSession(&sessions);

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

    memcpy(out_buf, nv_read.buffer, nv_read.size);
    if (out_read_size)
        *out_read_size = nv_read.size;

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

    uint8_t *buf = (uint8_t *)malloc(slot->size);
    if (!buf)
        return SBC_MEM_ERR;

    uint16_t read_size = 0;
    SBCStatus st = SBC_NvReadBuffer(ctx, slot, buf, slot->size, &read_size);
    if (st != SBC_OK) {
        free(buf);
        return st;
    }

    printf(C_BLU "\n[INFO] NV_Read %s (0x%08X) size=%u\n" C_RST,
           slot->name, slot->index, read_size);

    hexdump_color(buf, read_size);

    free(buf);
    return SBC_OK;
}

/* ============================================================
 *  NV <-> file helpers
 * ============================================================ */

/**
 * @brief Read NV data and save to a binary file.
 *
 * @param path Filesystem path to write (will be overwritten).
 */
SBCStatus SBC_NvReadToFile(SBC_TPM_CTX *ctx,
                           const SBC_NV_SLOT *slot,
                           const char *path)
{
    if (!ctx || !slot || !path)
        return SBC_ARG_ERR;

    uint8_t *buf = (uint8_t *)malloc(slot->size);
    if (!buf)
        return SBC_MEM_ERR;

    uint16_t read_size = 0;
    SBCStatus st = SBC_NvReadBuffer(ctx, slot, buf, slot->size, &read_size);
    if (st != SBC_OK) {
        free(buf);
        return st;
    }

    FILE *fp = fopen(path, "wb");
    if (!fp) {
        fprintf(stderr, C_RED "[ERROR] fopen('%s'): %s\n" C_RST,
                path, strerror(errno));
        free(buf);
        return SBC_FAIL;
    }

    size_t written = fwrite(buf, 1, read_size, fp);
    if (written != read_size) {
        fprintf(stderr, C_RED "[ERROR] fwrite('%s'): wrote=%zu, expected=%u\n" C_RST,
                path, written, read_size);
        fclose(fp);
        free(buf);
        return SBC_FAIL;
    }

    fclose(fp);
    free(buf);

    printf(C_GRN "[INFO] NV %s (0x%08X) dumped to file '%s' (%u bytes)\n" C_RST,
           slot->name, slot->index, path, read_size);

    return SBC_OK;
}

/**
 * @brief Load binary file and write its contents to NV.
 *
 * File size must exactly match NV slot size.
 */
SBCStatus SBC_NvWriteFromFile(SBC_TPM_CTX *ctx,
                              const SBC_NV_SLOT *slot,
                              const char *path,
                              uint32_t expected_crc)
{
    if (!ctx || !slot || !path)
        return SBC_ARG_ERR;

    FILE *fp = fopen(path, "rb");
    if (!fp) {
        fprintf(stderr, C_RED "[ERROR] fopen('%s'): %s\n" C_RST,
                path, strerror(errno));
        return SBC_FAIL;
    }

    if (fseek(fp, 0, SEEK_END) != 0) {
        fprintf(stderr, C_RED "[ERROR] fseek('%s'): %s\n" C_RST,
                path, strerror(errno));
        fclose(fp);
        return SBC_FAIL;
    }

    long fsize = ftell(fp);
    if (fsize < 0) {
        fprintf(stderr, C_RED "[ERROR] ftell('%s'): %s\n" C_RST,
                path, strerror(errno));
        fclose(fp);
        return SBC_FAIL;
    }

    if ((uint16_t)fsize != slot->size) {
        fprintf(stderr, C_RED "[ERROR] File size mismatch: file=%ld, NV slot=%u\n" C_RST,
                fsize, slot->size);
        fclose(fp);
        return SBC_SIZE_ERR;
    }

    if (fseek(fp, 0, SEEK_SET) != 0) {
        fprintf(stderr, C_RED "[ERROR] fseek('%s') rewind: %s\n" C_RST,
                path, strerror(errno));
        fclose(fp);
        return SBC_FAIL;
    }

    uint8_t *buf = (uint8_t *)malloc(slot->size);
    if (!buf) {
        fclose(fp);
        return SBC_MEM_ERR;
    }

    size_t read_bytes = fread(buf, 1, slot->size, fp);
    fclose(fp);

    if (read_bytes != slot->size) {
        fprintf(stderr, C_RED "[ERROR] fread('%s'): read=%zu, expected=%u\n" C_RST,
                path, read_bytes, slot->size);
        free(buf);
        return SBC_FAIL;
    }

    SBCStatus st = SBC_NvWriteChecked(ctx, slot, buf, slot->size, expected_crc);
    free(buf);
    return st;
}

/* ============================================================
 *  NV CRC utilities
 * ============================================================ */

/**
 * @brief Compute CRC32 of NV contents.
 */
SBCStatus SBC_NvComputeCrc(SBC_TPM_CTX *ctx,
                           const SBC_NV_SLOT *slot,
                           uint32_t *out_crc)
{
    if (!ctx || !slot || !out_crc)
        return SBC_ARG_ERR;

    uint8_t *buf = (uint8_t *)malloc(slot->size);
    if (!buf)
        return SBC_MEM_ERR;

    uint16_t read_size = 0;
    SBCStatus st = SBC_NvReadBuffer(ctx, slot, buf, slot->size, &read_size);
    if (st != SBC_OK) {
        free(buf);
        return st;
    }

    *out_crc = crc32_calc(buf, read_size);
    free(buf);

    printf(C_CYN "[INFO] CRC32(%s) from NV = 0x%08X\n" C_RST,
           slot->name, *out_crc);

    return SBC_OK;
}

/**
 * @brief Verify NV contents against expected CRC.
 *
 * @return SBC_OK if CRC matches, SBC_CRC_ERR if mismatch, or other SBC/TMP errors.
 */
SBCStatus SBC_NvVerifyCrc(SBC_TPM_CTX *ctx,
                          const SBC_NV_SLOT *slot,
                          uint32_t expected_crc)
{
    if (!expected_crc) {
        fprintf(stderr, C_YEL "[WARN] Expected CRC is 0. Skipping verify.\n" C_RST);
        return SBC_ARG_ERR;
    }

    uint32_t crc = 0;
    SBCStatus st = SBC_NvComputeCrc(ctx, slot, &crc);
    if (st != SBC_OK)
        return st;

    if (crc != expected_crc) {
        fprintf(stderr,
                C_RED "[ERROR] CRC mismatch for %s: expected=0x%08X, nv_crc=0x%08X\n" C_RST,
                slot->name, expected_crc, crc);
        return SBC_CRC_ERR;
    }

    printf(C_GRN "[INFO] CRC32(%s) matched: 0x%08X\n" C_RST,
           slot->name, crc);

    return SBC_OK;
}

/* ============================================================
 *  NV table summary
 * ============================================================ */

/**
 * @brief Dump summary for all NV slots in the global table.
 *
 * For each slot:
 *   - Check existence
 *   - If exists, read size and CRC and print summary
 */
void SBC_NvDumpTable(SBC_TPM_CTX *ctx)
{
    if (!ctx || !ctx->sys) {
        fprintf(stderr, C_RED "[ERROR] SBC_NvDumpTable: invalid TPM context\n" C_RST);
        return;
    }

    printf(C_BLU "\n[INFO] NV Table Summary\n" C_RST);
    printf("Name    Index       Size   Exists   CRC32\n");
    printf("------  ----------  -----  -------  ----------\n");

    for (size_t i = 0; i < g_nv_table_count; ++i) {
        const SBC_NV_SLOT *slot = &g_nv_table[i];
        int exists = SBC_NvExists(ctx, slot->index);

        if (exists <= 0) {
            printf("%-6s  0x%08X  %5u    %s    %s\n",
                   slot->name,
                   slot->index,
                   slot->size,
                   (exists == 0) ? "NO" : "ERR",
                   "----------");
            continue;
        }

        uint32_t crc = 0;
        SBCStatus st = SBC_NvComputeCrc(ctx, slot, &crc);
        if (st != SBC_OK) {
            printf("%-6s  0x%08X  %5u    YES      %s\n",
                   slot->name,
                   slot->index,
                   slot->size,
                   "CRC-ERR");
            continue;
        }

        printf("%-6s  0x%08X  %5u    YES      0x%08X\n",
               slot->name,
               slot->index,
               slot->size,
               crc);
    }

    printf("\n");
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

/* ============================================================
 *  Test helpers
 * ============================================================ */

/**
 * @brief Fill a CERT buffer using TPM2_GetRandom().
 *        The buffer must be NV_CERT_SIZE (512 bytes).
 */
static bool SBC_FillRandomCert(SBC_TPM_CTX *ctx, uint8_t *out_buf)
{
    size_t remaining = NV_CERT_SIZE;
    uint8_t *p = out_buf;

    while (remaining > 0) {

        TPM2B_DIGEST rand = { .size = 0 };

        TSS2_RC rc = Tss2_Sys_GetRandom(
            ctx->sys,
            NULL,
            (remaining > 64 ? 64 : remaining),
            &rand,
            NULL
        );

        if (rc != TSS2_RC_SUCCESS) {
            fprintf(stderr, C_RED
                    "[ERROR] GetRandom failed: rc=0x%X (%s)\n" C_RST,
                    rc, Tss2_RC_Decode(rc));
            return false;
        }

        memcpy(p, rand.buffer, rand.size);
        p += rand.size;
        remaining -= rand.size;
    }

    return true;
}

/**
 * @brief Fill CERT1 buffer with TPM random bytes.
 */
static SBCStatus fill_cert_with_tpm_random(SBC_TPM_CTX *ctx)
{
    uint8_t *p = g_cert1;
    size_t remaining = NV_CERT_SIZE;

    while (remaining > 0) {

        TPM2B_DIGEST rand = { .size = 0 };
        TSS2_RC rc = Tss2_Sys_GetRandom(
            ctx->sys,
            NULL,
            (remaining > 64 ? 64 : remaining),   /* TPM max ≈ 64 bytes per call */
            &rand,
            NULL
        );

        if (rc != TSS2_RC_SUCCESS) {
            fprintf(stderr, C_RED "[ERROR] GetRandom failed: rc=0x%X (%s)\n" C_RST,
                    rc, Tss2_RC_Decode(rc));
            return rc;
        }

        memcpy(p, rand.buffer, rand.size);
        p += rand.size;
        remaining -= rand.size;
    }

    printf(C_GRN "[INFO] CERT1 buffer filled with TPM random (%u bytes)\n" C_RST,
           NV_CERT_SIZE);

    return SBC_OK;
}

/* ============================================================
 *  Test entry
 * ============================================================ */

/**
 * @brief Simple test routine for NV manager.
 *
 * This function:
 *   - Initializes TPM
 *   - Writes KEY1~KEY3 (test patterns) to NV
 *   - Writes CERT1~CERT3 from real cert files with random sizes
 *   - Reads all and prints hexdump
 *   - Prints NV table summary
 */
int sbc_nv_test_main(void)
{
    SBC_TPM_CTX ctx;
    SBCStatus st;

    /* Seed RNG for random cert sizes */
    srand((unsigned)time(NULL));

    /* TPM Init */
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

    /* Lookup NV slots */
    const SBC_NV_SLOT *slot_key1  = SBC_NvFindSlotByName("KEY1");
    const SBC_NV_SLOT *slot_key2  = SBC_NvFindSlotByName("KEY2");
    const SBC_NV_SLOT *slot_key3  = SBC_NvFindSlotByName("KEY3");

    const SBC_NV_SLOT *slot_cert1 = SBC_NvFindSlotByName("CERT1");
    const SBC_NV_SLOT *slot_cert2 = SBC_NvFindSlotByName("CERT2");
    const SBC_NV_SLOT *slot_cert3 = SBC_NvFindSlotByName("CERT3");

    if (!slot_key1 || !slot_key2 || !slot_key3 ||
        !slot_cert1 || !slot_cert2 || !slot_cert3)
    {
        fprintf(stderr, C_RED "[FATAL] NV slot not found in table\n" C_RST);
        SBC_TpmFinish(&ctx);
        return 1;
    }

    /* -----------------------------------------
     * KEY test patterns (KEY1~KEY3)
     * ----------------------------------------- */

    /* KEY1: use global g_key1 */
    uint8_t key2_buf[NV_KEY_SIZE];
    uint8_t key3_buf[NV_KEY_SIZE];

    /* KEY2: incremental pattern */
    for (int i = 0; i < NV_KEY_SIZE; i++) {
        key2_buf[i] = (uint8_t)(i + 1);
    }

    /* KEY3: 0xAA pattern */
    memset(key3_buf, 0xAA, sizeof(key3_buf));

    printf(C_BLU "\n===== TEST: KEY1~KEY3 =====\n" C_RST);

    /* ---------------- KEY1 ---------------- */
    printf(C_CYN "\n[TEST] Write KEY1\n" C_RST);
    st = SBC_NvWriteChecked(&ctx, slot_key1, g_key1, NV_KEY_SIZE, 0);
    if (st != SBC_OK) goto fail;

    st = SBC_NvReadHexdump(&ctx, slot_key1);
    if (st != SBC_OK) goto fail;

    /* ---------------- KEY2 ---------------- */
    printf(C_CYN "\n[TEST] Write KEY2\n" C_RST);
    st = SBC_NvWriteChecked(&ctx, slot_key2, key2_buf, NV_KEY_SIZE, 0);
    if (st != SBC_OK) goto fail;

    st = SBC_NvReadHexdump(&ctx, slot_key2);
    if (st != SBC_OK) goto fail;

    /* ---------------- KEY3 ---------------- */
    printf(C_CYN "\n[TEST] Write KEY3\n" C_RST);
    st = SBC_NvWriteChecked(&ctx, slot_key3, key3_buf, NV_KEY_SIZE, 0);
    if (st != SBC_OK) goto fail;

    st = SBC_NvReadHexdump(&ctx, slot_key3);
    if (st != SBC_OK) goto fail;


    /* -----------------------------------------
     * CERT1~CERT3: real certificate files
     *   - cert1.pem → CERT1
     *   - cert2.pem → CERT2
     *   - cert3.pem → CERT3
     *   Each with random used length (64~NV_CERT_SIZE)
     * ----------------------------------------- */

    printf(C_BLU "\n===== TEST: CERT1~CERT3 (real certs, random size) =====\n" C_RST);

    uint8_t cert_buf[NV_CERT_SIZE];
    size_t  cert_len = 0;

    /* ----------- CERT1 ----------- */
    printf(C_CYN "\n[TEST] Write CERT1 from cert1.pem\n" C_RST);

    if (!SBC_LoadCertRandomSize("cert1.pem", cert_buf, &cert_len))
        goto fail;

    st = SBC_NvWriteChecked(&ctx, slot_cert1, cert_buf, NV_CERT_SIZE, 0);
    if (st != SBC_OK) goto fail;

    st = SBC_NvReadHexdump(&ctx, slot_cert1);
    if (st != SBC_OK) goto fail;


    /* ----------- CERT2 ----------- */
    printf(C_CYN "\n[TEST] Write CERT2 from cert2.pem\n" C_RST);

    if (!SBC_LoadCertRandomSize("cert2.pem", cert_buf, &cert_len))
        goto fail;

    st = SBC_NvWriteChecked(&ctx, slot_cert2, cert_buf, NV_CERT_SIZE, 0);
    if (st != SBC_OK) goto fail;

    st = SBC_NvReadHexdump(&ctx, slot_cert2);
    if (st != SBC_OK) goto fail;


    /* ----------- CERT3 ----------- */
    printf(C_CYN "\n[TEST] Write CERT3 from cert3.pem\n" C_RST);

    if (!SBC_LoadCertRandomSize("cert3.pem", cert_buf, &cert_len))
        goto fail;

    st = SBC_NvWriteChecked(&ctx, slot_cert3, cert_buf, NV_CERT_SIZE, 0);
    if (st != SBC_OK) goto fail;

    st = SBC_NvReadHexdump(&ctx, slot_cert3);
    if (st != SBC_OK) goto fail;


    /* -----------------------------------------
     * NV table summary
     * ----------------------------------------- */
    printf(C_BLU "\n===== NV TABLE SUMMARY =====\n" C_RST);
    SBC_NvDumpTable(&ctx);

    SBC_TpmFinish(&ctx);
    return 0;

fail:
    fprintf(stderr, C_RED "\n[FATAL] NV test aborted due to error.\n" C_RST);
    SBC_TpmFinish(&ctx);
    return 1;
}


#if 0
/**
 * @brief Simple test routine for NV manager.
 *
 * This function:
 *   - Initializes TPM
 *   - Writes KEY1 (fixed pattern) and CERT1 (TPM random) to NV with CRC check
 *   - Reads KEY1 and CERT1 and prints hexdump
 *   - Dumps NV table summary
 */
int sbc_nv_test_main(void)
{
    SBC_TPM_CTX ctx;
    SBCStatus st;

    /* TPM Init */
    st = SBC_TpmInit(&ctx, "device:/dev/tpm0");
    if (st != SBC_OK) {
        fprintf(stderr, C_RED "[FATAL] TPM Init failed: 0x%08X (%s)\n" C_RST,
                st, Tss2_RC_Decode(st));
        return 1;
    }

    /* Lookup NV slots */
    const SBC_NV_SLOT *slot_key1  = SBC_NvFindSlotByName("KEY1");
    const SBC_NV_SLOT *slot_key2  = SBC_NvFindSlotByName("KEY2");
    const SBC_NV_SLOT *slot_key3  = SBC_NvFindSlotByName("KEY3");

    const SBC_NV_SLOT *slot_cert1 = SBC_NvFindSlotByName("CERT1");
    const SBC_NV_SLOT *slot_cert2 = SBC_NvFindSlotByName("CERT2");
    const SBC_NV_SLOT *slot_cert3 = SBC_NvFindSlotByName("CERT3");

    if (!slot_key1 || !slot_key2 || !slot_key3 ||
        !slot_cert1 || !slot_cert2 || !slot_cert3)
    {
        fprintf(stderr, C_RED "[FATAL] NV slot missing in table\n" C_RST);
        SBC_TpmFinish(&ctx);
        return 1;
    }

    /* -----------------------------------------
     * KEY Test Data
     * ----------------------------------------- */
    uint8_t key2_buf[NV_KEY_SIZE];
    uint8_t key3_buf[NV_KEY_SIZE];

    memcpy(key2_buf, g_key1, NV_KEY_SIZE);   /* KEY2 = KEY1 copy */
    for (int i = 0; i < NV_KEY_SIZE; i++)
        key3_buf[i] = 0xAA;                  /* KEY3 = 0xAA pattern */

    printf(C_BLU "\n===== TEST: KEY1~KEY3 =====\n" C_RST);

    /* ---------------- KEY1 ---------------- */
    printf(C_CYN "\n[TEST] Write KEY1\n" C_RST);
    st = SBC_NvWriteChecked(&ctx, slot_key1, g_key1, NV_KEY_SIZE, 0);
    if (st != SBC_OK) goto fail;

    st = SBC_NvReadHexdump(&ctx, slot_key1);
    if (st != SBC_OK) goto fail;

    /* ---------------- KEY2 ---------------- */
    printf(C_CYN "\n[TEST] Write KEY2\n" C_RST);
    st = SBC_NvWriteChecked(&ctx, slot_key2, key2_buf, NV_KEY_SIZE, 0);
    if (st != SBC_OK) goto fail;

    st = SBC_NvReadHexdump(&ctx, slot_key2);
    if (st != SBC_OK) goto fail;

    /* ---------------- KEY3 ---------------- */
    printf(C_CYN "\n[TEST] Write KEY3\n" C_RST);
    st = SBC_NvWriteChecked(&ctx, slot_key3, key3_buf, NV_KEY_SIZE, 0);
    if (st != SBC_OK) goto fail;

    st = SBC_NvReadHexdump(&ctx, slot_key3);
    if (st != SBC_OK) goto fail;


    /* -----------------------------------------
     * CERT1~CERT3 테스트 (512바이트 랜덤)
     * ----------------------------------------- */
    printf(C_BLU "\n===== TEST: CERT1~CERT3 (TPM Random) =====\n" C_RST);

    uint8_t cert_buf[NV_CERT_SIZE];

    /* TPM Random 채우기 공통 코드 (Inline) */
    #define FILL_CERT_RANDOM()                                      \
        do {                                                        \
            size_t remain = NV_CERT_SIZE;                           \
            uint8_t *p = cert_buf;                                  \
            while (remain > 0) {                                    \
                TPM2B_DIGEST rand = { .size = 0 };                   \
                size_t req = (remain > 64 ? 64 : remain);            \
                TSS2_RC rc = Tss2_Sys_GetRandom(                     \
                    ctx.sys, NULL, req, &rand, NULL);                \
                if (rc != TSS2_RC_SUCCESS) {                         \
                    fprintf(stderr, C_RED                            \
                            "[ERROR] GetRandom failed: 0x%X (%s)\n", \
                            rc, Tss2_RC_Decode(rc));                 \
                    goto fail;                                       \
                }                                                    \
                memcpy(p, rand.buffer, rand.size);                   \
                p += rand.size;                                      \
                remain -= rand.size;                                 \
            }                                                        \
        } while (0)

    /* ---------------- CERT1 ---------------- */
    printf(C_CYN "\n[TEST] Write CERT1\n" C_RST);
    FILL_CERT_RANDOM();
    st = SBC_NvWriteChecked(&ctx, slot_cert1, cert_buf, NV_CERT_SIZE, 0);
    if (st != SBC_OK) goto fail;

    st = SBC_NvReadHexdump(&ctx, slot_cert1);
    if (st != SBC_OK) goto fail;

    /* ---------------- CERT2 ---------------- */
    printf(C_CYN "\n[TEST] Write CERT2\n" C_RST);
    FILL_CERT_RANDOM();
    st = SBC_NvWriteChecked(&ctx, slot_cert2, cert_buf, NV_CERT_SIZE, 0);
    if (st != SBC_OK) goto fail;

    st = SBC_NvReadHexdump(&ctx, slot_cert2);
    if (st != SBC_OK) goto fail;

    /* ---------------- CERT3 ---------------- */
    printf(C_CYN "\n[TEST] Write CERT3\n" C_RST);
    FILL_CERT_RANDOM();
    st = SBC_NvWriteChecked(&ctx, slot_cert3, cert_buf, NV_CERT_SIZE, 0);
    if (st != SBC_OK) goto fail;

    st = SBC_NvReadHexdump(&ctx, slot_cert3);
    if (st != SBC_OK) goto fail;


    /* -----------------------------------------
     * 전체 Summary
     * ----------------------------------------- */
    printf(C_BLU "\n===== NV TABLE SUMMARY =====\n" C_RST);
    SBC_NvDumpTable(&ctx);

    SBC_TpmFinish(&ctx);
    return 0;

fail:
    fprintf(stderr, C_RED "\n[FATAL] NV test aborted due to error.\n" C_RST);
    SBC_TpmFinish(&ctx);
    return 1;
}
#endif
