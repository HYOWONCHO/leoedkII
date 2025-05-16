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
 */
EFI_STATUS SBC_ReadFile(EFI_HANDLE ImageHandle, CHAR16 *FileNames, LV_t *out);

SBCStatus  SBC_GetFileSize(CHAR16 *FileName, UINTN  *FileSize);

UINTN  SBC_FileSysFindHndl(EFI_HANDLE *handle);
#endif
