/********************************************************************************
 * Copyright (C) 2024 by Security Platform Inc.                                 *
 * This file is part of the SBC Project.                                        *
 *                                                                              *
 * This software contains confidential and proprietary information of           *
 * Security Platform Inc. Unauthorized reproduction, distribution, or           *
 * disclosure of this software, in whole or in part, is strictly prohibited.    *
 ********************************************************************************/

#ifndef __SBC_KDF_H__
#define __SBC_KDF_H__


/**
 * @fn SBCStatus SBC_RngGeneration(UINT8 *seed, UINTN szseed, UINTN szrng, UINT8 *rngdata)
 * @brief Generate random data using hardware or software RNG.
 *
 * @param[in]  seed     Pointer to a buffer containing seed data (optional).
 *                      If @c NULL, the function uses an internal entropy source.
 * @param[in]  szseed   Length of the seed buffer, in bytes.
 *                      Can be 0 if @p seed is not provided.
 * @param[in]  szrng    Number of random bytes to generate.
 * @param[out] rngdata  Pointer to a buffer that receives the generated random data.
 *                      The buffer must be at least @p szrng bytes long.
 *
 * @retval SBCOK         Random data successfully generated.
 * @retval SBCFAIL       Random generation failed due to entropy source error.
 * @retval SBCNULLP      One or more input pointers are NULL.
 * @retval SBCINVPARAM   Invalid size or parameter value.
 * @retval SBCCRYPTO     Hardware RNG or entropy engine error.
 */
SBCStatus SBC_RngGeneration(UINT8 *seed, UINTN szseed, UINTN szrng, UINT8 *rngdata);


/**
 * @fn SBCStatus SBC_HKdfSha256(kdf_t *k, LV_t *out)
 * @brief Derive a cryptographic key using HKDF with SHA-256.
 *
 * @param[in]  k     Pointer to a @ref kdf_t structure containing HKDF parameters:
 *                   - `salt`  — Optional random salt value.
 *                   - `ikm`   — Input Keying Material (base key input).
 *                   - `info`  — Optional context/application-specific information.
 *                   - `len`   — Desired length of the output key.
 * @param[out] out   Pointer to an @ref LV_t structure that receives the derived key.
 *                   The buffer must be allocated to accommodate the requested length.
 *
 * @retval SBCOK         Key derivation completed successfully.
 * @retval SBCFAIL       HKDF computation failed (e.g., HMAC operation failure).
 * @retval SBCNULLP      One or more input pointers are NULL.
 * @retval SBCINVPARAM   Invalid HKDF parameters (e.g., zero-length key or salt).
 * @retval SBCCRYPTO     SHA-256 or HMAC computation error occurred.
 *
 */
SBCStatus SBC_HKdfSha256(kdf_t *k, LV_t *out);

#endif

