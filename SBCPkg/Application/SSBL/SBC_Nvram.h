/********************************************************************************
 * Copyright (C) 2024 by Security Platform Inc.                                 *
 * This file is part of the SBC Project.                                            *
 *                                                                              *
 * This software contains confidential and proprietary information of           *
 * Security Platform Inc. Unauthorized reproduction, distribution, or           *
 * disclosure of this software, in whole or in part, is strictly prohibited.    *
 ********************************************************************************/


#ifndef _SBC_NVRAM_H_
#define _SBC_NVRAM_H_

#define SBC_NVRAM_MAGIC_ID      0x53424300

typedef enum {
    //
    // Reset Request
    //
    SBC_BOOT_RESET_REQ_FSBL             = SBC_NVRAM_MAGIC_ID | 0x1,
    SBC_BOOT_RESET_REQ_SSBL,
    SBC_BOOT_RESET_REQ_FACTORY,
    SBC_BOOT_RESET_REQ_NORMAL,
    SBC_BOOT_RESET_REQ_UPDATE,
    //
    // Shutdown Request
    //
    SBC_BOOT_SHDN_REQ_FSBL,
    SBC_BOOT_SHDN_REQ_SSBL,
    SBC_BOOT_SHDN_REQ_FACTORY,
    SBC_BOOT_SHDN_REQ_NORMAL,
    SBC_BOOT_SHDN_REQ_UPDATE,
#ifdef _UNIT_TEST_ON_
    //
    // Unit Test Boot Condition
    //
    SBC_BOOT_UNIT_SHDN_REQ_FSBL,
    SBC_BOOT_UNIT_SHDN_REQ_SSBL,
    SBC_BOOT_SHDN_SFR_006,
    SBC_BOOT_SHDN_SFR_006_TAMPER,
    SBC_BOOT_SHDN_SFR_003,
#endif
    SBC_BOOT_ORDER_UNKNOWN             
}sbc_boot_varible_t;

/**
 * @fn SBC_NvramInit
 * @brief Initializes the SBC NVRAM subsystem.
 * 
 * @param[in] priv  Optional private context or configuration pointer. May be NULL if unused.
 */
VOID SBC_NvramInit(VOID *priv);

/**
 * @fn SBC_NvramDeInit
 * @brief Deinitializes the SBC NVRAM subsystem.
 * 
 * @param[in] priv  Optional private context or configuration pointer. May be NULL if unused.
 */
VOID SBC_NvramDeInit(VOID *priv);


//EFI_STATUS SBC_NvramListAllVariables(VOID);


/**
 * @fn SBC_NvramGetVar
 * @brief Retrieves a variable from EFI NVRAM into a caller-provided buffer.
 *
 * @param[in]  varname   Pointer to a null-terminated UTF-16 string representing the variable name.
 * @param[out] payload   Pointer to a buffer where the variable's data will be stored.
 * @param[in,out] sz_pl  Pointer to a variable holding the size of the payload buffer.
 *                       On input, it specifies the buffer size.
 *                       On output, it receives the actual size of the data read.
 *
 * @retval EFI_SUCCESS           The variable was successfully retrieved.
 * @retval EFI_BUFFER_TOO_SMALL The buffer is too small; `sz_pl` contains required size.
 * @retval EFI_NOT_FOUND         The variable does not exist in NVRAM.
 * @retval EFI_INVALID_PARAMETER One or more parameters are NULL or invalid.
 */
EFI_STATUS SBC_NvramGetVar(VOID *varname, VOID *payload, VOID *sz_pl);

/**
 * @fn SBC_NvramSetVar
 * @brief Writes a variable to EFI NVRAM with the specified payload and size.
 *
 * @param[in] varname   Pointer to a null-terminated UTF-16 string representing the variable name.
 * @param[in] payload   Pointer to the data buffer to be written.
 * @param[in] sz_pl     Pointer to a variable holding the size of the payload in bytes.
 *
 * @retval EFI_SUCCESS           The variable was successfully written to NVRAM.
 * @retval EFI_INVALID_PARAMETER One or more parameters are NULL or invalid.
 * @retval EFI_WRITE_PROTECTED   The variable cannot be modified due to platform restrictions.
 * @retval EFI_OUT_OF_RESOURCES  Insufficient memory to complete the operation.
 * @retval EFI_DEVICE_ERROR      A hardware or firmware error occurred during the write.
 */
EFI_STATUS SBC_NvramSetVar(VOID *varname, VOID *payload, VOID *sz_pl);

//EFI_STATUS SBC_BiosReadBootOrder(VOID);


#endif
