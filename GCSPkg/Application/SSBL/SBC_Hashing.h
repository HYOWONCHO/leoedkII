/********************************************************************************
 * Copyright (C) 2024 by Security Platform Inc.                                 *
 * This file is part of the SBC Project.                                        *
 *                                                                              *
 * This software contains confidential and proprietary information of           *
 * Security Platform Inc. Unauthorized reproduction, distribution, or           *
 * disclosure of this software, in whole or in part, is strictly prohibited.    *
 ********************************************************************************/



#ifndef __SBC_HASHING_H
#define __SBC_HASHING_H

/**
 * @fn SBCStatus SBC_HashCompute(VOID **handle, UINT8 *message, UINTN msglen,
 *     UINT8 *digest)
 * @brif Obtain the Hash of message
 *
 * @param[IN,OUT]   handle    Handle of hash operation context ( but not in use )
 * @param[IN]       message   Buffer containing the message of hash
 * @param[IN]       msglen    Size of buffer in bytes
 * @param[OUT]      digest    Buffer where the hash is to be written
 *
 * @retval SBCOK         Random data successfully generated.
 * @retval SBCFAIL       Random generation failed due to entropy source error.
 * @retval SBCNULLP      One or more input pointers are NULL.
 * @retval SBCINVPARAM   Invalid size or parameter value.
 * @retval SBCCRYPTO     Hardware RNG or entropy engine error.
 */
SBCStatus SBC_HashCompute(VOID **handle, UINT8 *message, UINTN msglen, UINT8 *digest) ;

/**
 * @fn SBCStatus SBC_HmacCompute(VOID *handle, UINT8 *mackey, UINTN keysz,
                          UINT8 *msg, UINTN msglen, UINT8 *hmacvalue)
 * @brief Computes the HMAC-SHA digest of a Message buffer 
 * 
 * @author leoc (4/28/25)
 * 
 * @param handle    Pointer to the HMAC handle context
 * @param mackey    Pointer to user-suppiled key
 * @param keysz     Key size in bytes
 * @param msg       Pointer to the buffer containing the digest
 *                  message
 * @param msglen    Message length in bytes
 * @param hmacvalue Pointer to a buffer that receive the
 *                  computed HMAC 
 * 
 * @return BOOLEAN 
 */
SBCStatus SBC_HmacCompute(VOID *handle, UINT8 *mackey, UINTN keysz,
                          UINT8 *msg, UINTN msglen, UINT8 *hmacvalue);




#endif
