#ifndef SBC_FILECTRL_H
#define SBC_FILECTRL_H

#include "SBC_ErrorType.h"

                                                                                                             
                                                                                                                                                                               
//SBCStatus SBC_CreateFile(EFI_HANDLE h, CHAR16 *fname);                                                     
                                                                                                             
/*!                                                                                                          
    \brief Define the RAW Partition information                                                              
*/                                                                                                           
                                                                                                             
#define SBC_RPTN_FIRST_SKIP_BYTES           0x40 // 64                                                       
#define SBC_RPTN_INFO_LEN                   0x40                                                             
                                                                                                             
                                                                                                             
/*!                                                                                                          
 * SBC Raw Partition Header structure                                                                        
 *                                                                                                           
 * \var sbc_rptn_header_t::value - SBC Header information buffer                                             
 * \var sbc_rptn_header_t::m - Buffer regard to "SKIP" and "INFO"                                            
 *                                                                                                           
 * \author leoc (6/4/25)                                                                                     
 */                                                                                                          
typedef union _sbc_rtpn_header_t {
    struct {
        UINT8 skip[SBC_RPTN_INFO_LEN]; /**< SKIP Buffer, but it has a Magic ID to find the device in UEFI*/
        UINT8 info[SBC_RPTN_INFO_LEN]; /*!< partition information*/
    }m;

    UINT8 value[SBC_RPTN_INFO_LEN << 1]; //!< Header data buffer
                                         ///< Header data buffer

}sbc_rptn_header_t;
                                                                                                             
                                                                                                             
/*!                                                                                                          
 * Read the Data from specified file                                                                         
 *                                                                                                           
 * \author leoc (5/14/25)                                                                                    
 *                                                                                                           
 * \param[in] ImageHandle                                                                                    
 * \param[in] FileNames                                                                                      
 * \param[out] out                                                                                           
 *                                                                                                           
 * \return EFI_STATUS                                                                                        
 * \note                                                                                                     
 *  MUST call the SBC_FileSysFindHndl to obtain a FileProtocolHandle before using this function              
 */                                                                                                          
EFI_STATUS SBC_ReadFile(EFI_HANDLE ImageHandle, CHAR16 *FileNames, LV_t *out);                               
                                                                                                             
                                                                                                             
/*!                                                                                                          
 * Get the size of the file for specified file.                                                              
 *                                                                                                           
 * \author leoc (6/4/25)                                                                                     
 *                                                                                                           
 * \param[in] FileName      File Name buffer                                                                 
 * \param[out] FileSize     Size of File for specified FileName                                              
 *                                                                                                           
 * \return On success, return the SBCOK, otherwise, return the approiate value.                              
 */                                                                                                          
SBCStatus  SBC_GetFileSize(CHAR16 *FileName, UINTN  *FileSize);                                              
                                                                                                             
/*!                                                                                                          
 * Find the File related protocol handle                                                                     
 *                                                                                                           
 * \author leoc (6/4/25)                                                                                     
 *                                                                                                           
 * \param[OUT] handle File protocol handle buffer                                                            
 *                                                                                                           
 * \return On success, return the handle count, otherwise, return the zero                                   
 */                                                                                                          
UINTN  SBC_FileSysFindHndl(EFI_HANDLE *handle);                                                              
                                                                                                             
/*!                                                                                                          
 * Create the File                                                                                           
 *                                                                                                           
 * \author leoc (5/21/25)                                                                                    
 *                                                                                                           
 * \param h                                                                                                  
 * \param fname                                                                                              
 *                                                                                                           
 * \return SBCStatus                                                                                         
 * \note                                                                                                     
 *  MUST call the SBC_FileSysFindHndl to obtain a FileProtocolHandle before using this function              
 */                                                                                                          
SBCStatus  SBC_CreateFile(EFI_HANDLE h, CHAR16 *fname);                                                      
                                                                                                             
/*!                                                                                                          
 * Create the directory                                                                                      
 *                                                                                                           
 * \author leoc (5/21/25)                                                                                    
 *                                                                                                           
 * \param h                                                                                                  
 * \param fname                                                                                              
 *                                                                                                           
 * \return SBCStatus                                                                                         
 * \note                                                                                                     
 *  MUST call the SBC_FileSysFindHndl to obtain a FileProtocolHandle before using this function              
 */                                                                                                          
SBCStatus  SBC_CreateDirectory(EFI_HANDLE h, CHAR16 *fname);                                                 
                                                                                                             
/*!                                                                                                          
 *                                                                                                           
 * \fn SBCStatus SBC_ReadRawPrtHeaderInfo(IN VOID *blkhnd, OUT VOID *rdbuf, IN UINT32 *rdlen)                   
 *                                                                                                           
 * \brief Load the raw-partition header information                                                          
 *                                                                                                           
 * \author leoc (6/4/25)                                                                                     
 *                                                                                                           
 * \param[in] blkhnd        Handle pointer for the BlockIo device  operation                                 
 * \param[out] rdbuf        Pointer to load the Header information                                           
 * \param[in,out] rdlen     Length of read bytes                                                             
 *                                                                                                           
 * \return On success, return the SBCOK, otherwise, return the approiate value.                              
 */                                                                                                          
SBCStatus SBC_ReadRawPrtHeaderInfo(VOID *blkhnd, VOID *rdbuf,  UINT32 *rdlen);
                           
                           
/*!
 * \fn SBCStatus SBC_RawPrtReadBlock(VOID *blkhnd, VOID *rdbuf,  UINT32 *rdlen, UINTN rlba)
 * 
 * \author leoc (6/5/25)
 * 
 * \param blkhnd Context handle for Block IO
 * \param rdbuf  Pointer to the destination buffer for the data
 * \param rdlen  Size of rdbuf
 * \param rlba   Starting Logical Block Address to read from
 * 
 * \retval  SBCOK   Data ws read correctly form the device
 * \retval  Othrewise value is Error 
 */
SBCStatus SBC_RawPrtReadBlock(VOID *blkhnd, VOID *rdbuf,  UINT32 *rdlen, UINTN rlba);     
                      
/*!
 * \fn SBCStatus  SBC_FindBlkIoHandle(OUT VOID **hblk)
 * 
 * Find the Block Protocol interface for SBC Raw Partition 
 * 
 * \author leoc (6/5/25)
 * 
 * \param hblk   
 * 
 * \return SBCStatus 
 */
SBCStatus  SBC_FindBlkIoHandle(OUT VOID **hblk);  
                    
/*!
 * \fn SBCStatus  SBC_RawPrtBlockWrite(VOID *blkio, UINT8 *wrbuf, UINT32 wrlen, UINT32 wrlba)
 * 
 * Write the data in Raw Partition 
 * 
 * \author leoc (6/9/25)
 * 
 * \param blkio  
 * \param wrbuf  
 * \param wrlen  
 * \param wrlba  
 * 
 * \return SBCStatus 
 */
SBCStatus  SBC_RawPrtBlockWrite(VOID *blkio, UINT8 *wrbuf, UINT32 wrlen, UINT32 wrlba);                    

#endif
