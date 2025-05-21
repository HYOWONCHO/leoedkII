#ifndef SBC_FILECTRL_H
#define SBC_FILECTRL_H


#include "SBC_ErrorType.h"
//SBCStatus SBC_CreateFile(EFI_HANDLE h, CHAR16 *fname);


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

SBCStatus  SBC_GetFileSize(CHAR16 *FileName, UINTN  *FileSize);

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
#endif
