/********************************************************************************
 * Copyright (C) 2024 by Security Platform Inc.                                 *
 * This file is part of the SBC Project.                                        *
 *                                                                              *
 * This software contains confidential and proprietary information of           *
 * Security Platform Inc. Unauthorized reproduction, distribution, or           *
 * disclosure of this software, in whole or in part, is strictly prohibited.    *
 ********************************************************************************/

#ifndef __SBCErrorType
#define __SBCErrorType

#include <Library/UefiLib.h>


#include "SBC_TypeDefs.h"

/**
 * @enum SBCStatus
 * @brief Defines return codes used throughout the SBC (Secure Boot Core) framework.
 */
typedef enum {
   SBCOK                = 0,    /**< Operation completed successfully. */
   SBCFAIL              = 300,  /**< General failure. */
   SBCINVPARAM          = 301,  /**< Invalid parameter. */
   SBCNULLP             = 302,  /**< Null pointer encountered. */
   SBCZEROL             = 303,  /**< Zero-length input or buffer. */
   SBCNOTFND            = 304,  /**< Requested item not found. */
   SBCBADFMT            = 305,  /**< Bad format detected. */
   SBCFMMTTYP           = 306,  /**< Unsupported or incorrect format type. */
   SBCNOSPC             = 307,  /**< Not enough space for output. */
   SBCIO                = 308,  /**< I/O error occurred. */
   SBCFAULT             = 309,  /**< Invalid memory address or fault. */
   SBCBUSY              = 310,  /**< Resource is busy or locked. */
   SBCTIME              = 311,  /**< Operation timed out. */
   SBCCOMM              = 312,  /**< Communication error. */
   SBCPROTO             = 313,  /**< Protocol violation or mismatch. */
   SBCNOTSUP            = 314,  /**< Operation not supported. */
   SBCENCFAIL           = 315,  /**< Encryption failed. */
   SBCDECFAIL           = 316,  /**< Decryption failed. */
   SBCBSANSWNOTFND      = 317,  /**< Base answer not found. */
   SBCUNKNOWN                   /**< Unknown or undefined error. */
} SBCStatus;

#ifdef _TEST_ERROR_SET_
#define ERR_NVM_VARSTR          L"ErrorSet"

#define ERR_NVM_NOERROR         0xC0

#define ERR_MIGRATION_KEY       0xC1
#define ERR_BASEANSWR_READ      0xC2
#define ERR_BASEANSWR_WRITE     0xC3
#define ERR_SECKEY_CREATE       0xC4

#define ERR_PROTSW_DEC          0xC5
#define ERR_PROTSW_ENC          0xC6
#define ERR_PROTSW_WRITE        0xC7

#define ERR_OSID_KEY            0xC8
#define ERR_BASEANSWR_DEC       0xC9
#define ERR_BASEANSWR_ENC       0xCA

#define ERR_PREV_FW_NOTEXIST    0xCB
#endif



#endif
