#ifndef __SBC_KDF_H__
#define __SBC_KDF_H__

SBCStatus SBC_RngGeneration(UINT8 *seed, UINTN szseed, UINTN szrng, UINT8 *rngdata);

/*!
 * Derive SHA256 HMAC-based Extract key Derivation Function (HKDF). 
 * 
 * \author leoc (5/20/25)
 * 
 * \param[in] k      Pointer to the kdf_t structure
 * \param[out] out    Pointer to buffer to receive the HKDF 
 * 
 * \return SBCStatus 
 */
SBCStatus  SBC_HKdfSha256(kdf_t *k, LV_t  *out);
#endif

