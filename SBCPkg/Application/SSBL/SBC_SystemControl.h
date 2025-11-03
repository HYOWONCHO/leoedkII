/********************************************************************************
 * Copyright (C) 2024 by Security Platform Inc.                                 *
 * This file is part of the SBC Project.                                        *
 *                                                                              *
 * This software contains confidential and proprietary information of           *
 * Security Platform Inc. Unauthorized reproduction, distribution, or           *
 * disclosure of this software, in whole or in part, is strictly prohibited.    *
 ********************************************************************************/

#ifndef __SYSTEM_CONTROL_H
#define __SYSTEM_CONTROL_H
#include "SBC_ErrorType.h"


#pragma pack(push, 1)
/**
 * @struct sb_rcv_proc_t
 * @brief Recovery process context structure for Secure Boot / Protected SW.
 */

/** @var sb_rcv_proc_t::migkey
 *  @brief Pointer to the migration key used for key rotation or re-encryption.
 *
 *  This field references the migration key buffer used in protected
 *  software key update operations.
 */

/** @var sb_rcv_proc_t::osid
 *  @brief Pointer to the OS identifier data.
 *
 *  Identifies the operating system or firmware instance participating
 *  in the secure boot or recovery process.
 */

/** @var sb_rcv_proc_t::baseans
 *  @brief Pointer to the base answer or authentication token.
 *
 *  Used to validate integrity or identity during anti-tampering verification.
 */

/** @var sb_rcv_proc_t::handle
 *  @brief Handle to the underlying secure partition or context.
 *
 *  Provides access to the raw device or partition storing protected
 *  software and metadata.
 */

/** @var sb_rcv_proc_t::whitels
 *  @brief Pointer to the whitelist data structure.
 *
 *  Contains a list of authorized binaries, certificates, or identifiers
 *  used to verify the legitimacy of loaded software.
 */
typedef struct _sb_rcv_proc_t {
    VOID *migkey;    /**< Pointer to migration key buffer. */
    VOID *osid;      /**< Pointer to OS identifier. */
    VOID *baseans;   /**< Pointer to base answer (auth token). */
    VOID *handle;    /**< Pointer to secure partition handle. */
    VOID *whitels;   /**< Pointer to whitelist data structure. */
} sb_rcv_proc_t;

#pragma pack(pop)


/**
 * @fn VOID SBC_ShutdownSystem(VOID)
 * @brief Perform a controlled system shutdown.
 *
 * @retval None
 */
VOID SBC_ShutdownSystem(VOID);

/**
 * @fn VOID SBC_RebootSystem(VOID)
 * @brief Perform a controlled system reboot.
 *
 * @retval None
 */
VOID SBC_RebootSystem(VOID);


/**
 * @fn SBCStatus SBC_SecureBootCheck(VOID *priv)
 * @brief Perform secure boot integrity and authenticity verification.
 *
 * @param[in] priv  Pointer to a private context or configuration structure
 *                  used during the secure boot process.  
 *                  This may reference internal platform or cryptographic data.
 *
 * @retval SBCOK         Secure boot verification completed successfully.
 * @retval SBCFAIL       Secure boot integrity check failed.
 * @retval SBCNULLP      Input pointer is NULL or context invalid.
 * @retval SBCINVPARAM   Invalid secure boot configuration or key reference.
 * @retval SBCCRYPTO     Cryptographic or signature verification failure.
 *
 */
SBCStatus SBC_SecureBootCheck(VOID *priv);

#endif
