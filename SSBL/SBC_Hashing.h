#ifndef __SBC_HASHING_H
#define __SBC_HASHING_H




/**
 * @brif Obtain the Hash of message
 *
 * @param[IN,OUT]   handle    Handle of hash operation context ( but not in use )
 * @param[IN]       message   Buffer containing the message of hash
 * @param[IN]       msglen    Size of buffer in bytes
 * @param[OUT]      digest    Buffer where the hash is to be written
 *
 * @return On success, return the SBCOK, otherwise appropriate value
 */
SBCStatus SBC_HashCompute(VOID **handle, UINT8 *message, UINTN msglen, UINT8 *digest) ;

/**
 * Computes the HMAC-SHA digest of a Message buffer 
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
