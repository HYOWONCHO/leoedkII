/********************************************************************************
 * Copyright (C) 2024 by Security Platform Inc.                                 *
 * This file is part of the SBC Project.                                            *
 *                                                                              *
 * This software contains confidential and proprietary information of           *
 * Security Platform Inc. Unauthorized reproduction, distribution, or           *
 * disclosure of this software, in whole or in part, is strictly prohibited.    *
 ********************************************************************************/

#ifndef SBC_FILECTRL_H
#define SBC_FILECTRL_H

#include "SBC_ErrorType.h"

#define BOOT_VENDOR_BASEDIR     L"\\EFI\\rocky"

#define BOOT_MODE_FNAME         L"\\EFI\\BOOT\\bootmode"
#define BOOT_MODE_STRNRORMAL    "normal"
#define BOOT_MODE_STRUPDATE     "update"
#define BOOT_MODE_STRFACTORY    "factory"



/**
 * @enum boot_mode_t
 * @brief Defines the various boot modes supported by the system.
 */
typedef enum _t_boot_mode {
    BOOT_MODE_NONE      = 0,  /**< No boot mode specified. */
    BOOT_MODE_NORMAL,         /**< Normal boot mode. */
    BOOT_MODE_UPDATE,         /**< Firmware image update mode. */
    BOOT_MODE_RECOVERY,       /**< Recovery mode boot. */
    BOOT_MODE_FACTORY,        /**< Factory mode boot. */
    BOOT_MODE_UNKNOWN         /**< Unknown or unsupported boot mode. */
} boot_mode_t;
/**
 * @enum key_mode_t
 * @brief Defines the key handling mode used during secure boot or update.
 */
typedef enum _t_key_mode {
    KEY_MODE_NONE = 0,    /**< No key mode specified. */
    KEY_MODE_NORMAL,      /**< Normal key usage mode. */
    KEY_MODE_BOOT,        /**< Key used during boot-time validation. */
    KEY_MODE_UPDATE,      /**< Key used during firmware update. */
    KEY_MODE_UNKNOWN      /**< Unknown or unsupported key mode. */
} key_mode_t;

#pragma pack(push, 1)
/**
 * @struct bm_lookup_table_t
 * @brief Represents a key-value mapping used for boot mode or key mode lookup.
 */
typedef struct _t_bm_lookup_table {
    CHAR8 *key;     /**< String key representing the mode or identifier. */
    UINT32 val;     /**< Numeric value associated with the key. */
} bm_lookup_table_t;
#pragma pack(pop)


#define SBC_RAWPRT_DFLT_SHIFT                       0x9
#define SBC_RAWPRT_DFLT_BLK_SZ                      (1 << SBC_RAWPRT_DFLT_SHIFT)

#define SBC_FILE_RW_BLK(len)                        \
    ({                                              \
        UINT32 _x = len;                            \
        if(_x <= SBC_RAWPRT_DFLT_BLK_SZ) {          \
            _x = 0;                                 \
        }                                           \
        else {                                      \
            _x = len / SBC_RAWPRT_DFLT_BLK_SZ;      \
        }                                           \
        _x;                                         \
    })     
/*! 
    \defgroup   RawPartition        Raw Partition related data structure and defines
    \{
*/



#define SBC_RAW_PRTHDR_LBA                  0
/*! Raw Partition Identifier */
#define SBC_RAWPRT_MAGIC_ID                 0xAA55AA55 

/*! Partition Information Length */
#define SBC_PRTNIFO_LEN                     64

/*! Raw Partition Header skip bytes*/
#define SBC_HDR_SKIP_LEN                    46

/*! Boot pres length */
#define SBC_BOOT_PRES_LEN                   4

/*! Boot Mode */
#define SBC_BOOT_MODE_LEN                   2
#define SBC_KEY_MODE_LEN                    2
#define SBC_RECOVERY_LEN                    2

#pragma pack(push, 1)
/*!
    \struct rawprt_hdr_t
    \brief Raw Partition Header  structure
*/
typedef struct _rawprt_hdr_t {
    UINT32      magicid;                        /**< Identifier for SBC Raw-Partition */
    UINT8       prtinfo[SBC_PRTNIFO_LEN];       /**< Partition information */
    UINT8       reserv[SBC_HDR_SKIP_LEN];
    UINT16      bootmode;                        /**< Boot Mode */   
    UINT16      keymode;                        /*! Key Mode*/
    UINT16      rcvmode;                        /*! Recover mode */     
    UINT8       bootpres[SBC_BOOT_PRES_LEN];    /**< Boot pres */
    UINT8       bootpres_reserv[SBC_BOOT_PRES_LEN];    /**< Boot pres */
}rawprt_hdr_t;

#pragma pack(pop)

#define BOOT_BLKIO_DFTSZ                    0x00000200

#define BOOT_FW_SRTOFS                      0x00000200

#define BOOT_FSBL_OFS                       0x00000000      /**< FSBL Offset */
#define BOOT_SSBL_OFS                       0x00400000      /**< SSB Offset */
#define BOOT_OS_OFS                         0x00800000      /**< Operating System Offset */
#define BOOT_SW_OFS                         0x01C00000      /**< Boot Software offset */


#define BOOT_SECTOR1_OFS                    (0x00000000 | BOOT_FW_SRTOFS)
#define BOOT_SECTOR2_OFS                    (0x08000000 | BOOT_FW_SRTOFS)
#define BOOT_SECTOR3_OFS                    (0x10000000 | BOOT_FW_SRTOFS)

#define BOOT_IMG_LENB                       0x00000004
#define BOOT_FSBL_MAX                       0x00400000      /**< 4M */
#define BOOT_FSBL_IMGMAX                    (BOOT_FSBL_MAX - BOOT_IMG_LENB)


#define BOOT_SSBL_MAX                       0x00400000      /**< 4M */
#define BOOT_SSBL_IMGMAX                    (BOOT_SSBL_MAX - BOOT_IMG_LENB)


#define BOOT_OS_IMG_MB                      20
#define BOOT_OS_MAX                         (BOOT_OS_IMG_MB << 20)      /**< 20 M */
#define BOOT_OS_IMGMAX                      (BOOT_OS_MAX - BOOT_IMG_LENB)

#define BOOT_SW_IMG_MB                      100
#define BOOT_SW_MAX                         (BOOT_SW_IMG_MB << 20)      /**<  100 M */
#define BOOT_SW_IMGMAX                      (BOOT_SW_MAX - BOOT_IMG_LENB)


#define BOOT_FW_IMG_MB                      128
#define BOOT_FW_IMGMAX                      (BOOT_FW_IMG_MB << 20)

/*! \brief Addresss of Protected Software    */
#define BOOT_FW_PROT_SW_POS                 (0x01C00000 | BOOT_FW_SRTOFS)       


#define BOOT_FW_LBA_BLOCKS                  (BOOT_FW_IMGMAX / SBC_RAWPRT_DFLT_BLK_SZ)


/**
 * \brief Boot Firmware storage information 
 */
#pragma pack(1)
typedef union _boot_fw_inf_t {

    struct {
        UINT32  fsbln;
        UINT8   fsblimg[BOOT_FSBL_IMGMAX];
        UINT32  ssbln;
        UINT8   ssblimg[BOOT_SSBL_IMGMAX];
        UINT32  osln;
        UINT8   osimg[BOOT_OS_IMGMAX];
        UINT32  swn;
        UINT8   swimg[BOOT_SW_IMGMAX];
    }mbr;

    UINT8 value[BOOT_FW_IMGMAX];

}boot_fw_inf_t;

#pragma pack()


#define LEN_DFLT_OFS                    0x04

#define SYS_CONF_START_OFS              (0x18000000 | BOOT_FW_SRTOFS)
#define SYS_CONF_OSID_OFS               0x00000000
#define SYS_CONF_RES_OFS                0x00000040          /**< Reference offset */
#define SYS_CONF_ROOT_CA_OFS            0x00000080
#define SYS_CONF_DEVID_CRT_OFS          0x00000880
#define SYS_CONF_FWID_CRT_OFS           0x00001080
#define SYS_CONF_OSID_CRT_OFS           0x00001880
#define SYS_CONF_SW_LIST_OFS            0x00002080


#define SYS_OSID_LEN                    4
#define SYS_OSID_KEY_LEN                32
#define SYS_OSID_IV_LEN                 12
#define SYS_OSID_TAG_LEN                16
#define SYS_OSID_MAX_LEN                64

#define SYS_PRES_LEN                    4
#define SYS_PRES_RES_LEN                16
#define SYS_PRES_IV_LEN                 12
#define SYS_PRES_TAG_LEN                16
#define SYS_PRES_RESERVED               16
#define SYS_PRES_MAX_LEN                64

#define SYS_PRES_INFO_MAX               (SYS_PRES_LEN + SYS_PRES_RES_LEN + SYS_PRES_IV_LEN + SYS_PRES_TAG_LEN + SYS_PRES_RESERVED)

#define SYS_CERT_LEN                    (2<<10)
#define SYS_SWLIST_OFS_LEN              (8<<10)

#define SYS_SETTING_STORAGE_LEN         (SYS_OSID_MAX_LEN + SYS_PRES_MAX_LEN + SYS_CERT_LEN + SYS_CERT_LEN + SYS_CERT_LEN + SYS_CERT_LEN + SYS_SWLIST_OFS_LEN)

#pragma pack(1)
typedef union _osid_key_t {

    struct {
        UINT32      len;
        UINT8       key[SYS_OSID_KEY_LEN];
        UINT8       iv[SYS_OSID_IV_LEN];
        UINT8       tag[SYS_OSID_TAG_LEN];
    }m;

    UINT8 value[SYS_OSID_LEN + SYS_OSID_KEY_LEN + SYS_OSID_IV_LEN + SYS_OSID_TAG_LEN];
}osid_key_t;

typedef union _sys_pres_t  {

    struct {
        UINT32      len;
        UINT8       res[SYS_PRES_RES_LEN];
        UINT8       iv[SYS_PRES_IV_LEN];
        UINT8       tag[SYS_PRES_TAG_LEN];
        UINT8       reserved[SYS_PRES_RESERVED];
    }m;


    UINT8 value[SYS_PRES_INFO_MAX];

}sys_pres_t;

#pragma pack()
      
/*! \} */                                                                                                       
                                                                                                                                                                               
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
 * \param h       EFI image handle used to locate the file
   system.
 * \param fname   Pointer to the UTF-16 string representing the
   file name to create.
 *                                                                                                           
 * \return SBCStatus
 *         - SBCOK: File was successfully created.
 *         - SBCNULLP: Null pointer input detected.
 *         - SBCFAIL: File creation failed due to I/O or protocol error.                                                                                        
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
 * \param hblk   Context handle for Block IO
 * 
 * \retval  SBCOK   Data ws read correctly form the device
 * \retval  Othrewise value is Error 
 */
SBCStatus  SBC_FindBlkIoHandle(OUT VOID **hblk);  
                    
/*!
 * \fn SBCStatus  SBC_RawPrtBlockWrite(VOID *blkio, UINT8 *wrbuf, UINT32 wrlen, UINT32 wrlba)
 * 
 * \brief Write the data in Raw Partition block at the specified
   LBA
 * 
 * \author leoc (6/9/25)
 * 
 * \param blkio  Context handle for Block IO
 * \param wrbuf  Pointer to the buffer containing data to be
   written
 * \param wrlen  Length of the data to write, in bytes.
 * \param wrlba  Logicl Block Address where the data should be
   written
 * \return 
 *         - SBCOK: Write operation succeeded.
 *         - SBCNULLP: Null pointer encountered.
 *         - SBCFAIL: Write operation failed.
 *         - SBCIO: I/O error occurred during write
 */
SBCStatus  SBC_RawPrtBlockWrite(VOID *blkio, UINT8 *wrbuf, UINT32 wrlen, UINT32 wrlba);                    


/*!
 * \fn UINT32  SBC_ReadBootMode(VOID)
 * 
 * \brief Read the boot mode from /EFI/BOOT/boot_mode.txt file
 * \author leoc (6/17/25)
 * 
 * \param void   
 * 
 * \return None 
 */
UINT32  SBC_ReadBootMode(VOID);


/*!
 * \fn SBCStatus SBC_ProtectedSWWrite(VOID *blkio, 
                              VOID *buf, UINT32 *len, 
                              UINT32 bnkid)
 * \brief Protected SW blob write to Raw Partition
 * 
 * \author leonc (8/14/25)
 * 
 * \param blkio  Pointer to the block I/O interface or handle.
 * \param buf    Pointer to the buffer containing data to be
   written
 * \param len    Length of the data to write, in bytes.
 * \param bnkid  Protected SW Bank Index in Raw Partition 
 * 
 * \return 
 *         - SBCOK: Write operation succeeded.
 *         - SBCNULLP: Null pointer encountered.
 *         - SBCFAIL: Write operation failed.
 *         - SBCIO: I/O error occurred during writ
 */
SBCStatus SBC_ProtectedSWWrite(VOID *blkio, 
                              VOID *buf, UINT32 *len, 
                              UINT32 bnkid);

/*!
 * \fn SBCStatus SBC_ProtectedSWRead(VOID *blkio, 
                              VOID *buf, UINT32 *len, 
                              UINT32 bnkid)
 * \brief Protected SW blob write to Raw Partition
 * 
 * \author leonc (8/14/25)
 * 
 * \param blkio  Pointer to the block I/O interface or handle.
 * \param buf    Pointer to the buffer containing data to be
   read
 * \param len    Length of the data to read, in bytes.
 * \param bnkid  Protected SW Bank Index in Raw Partition 
 * 
 * \return 
 *         - SBCOK: Read operation succeeded.
 *         - SBCNULLP: Null pointer encountered.
 *         - SBCFAIL: Write operation failed.
 *         - SBCIO: I/O error occurred during writ
 */
SBCStatus SBC_ProtectedSWRead(VOID *blkio, 
                              VOID **buf, UINT32 *len, 
                              UINT32 bnkid);


/*!
 * 
 * \brief Write arbitrary bytes to a Block I/O device
 * 
 * \author leoc (9/24/25)
 * 
 * \param blk    Pointer to EFI_BLOCK_IO_PROTOCOL
 * \param off    Byte offset from the start to media to begin writting
 * \param sz     Number of bytes to write.
 * \param buf    Source bufferw to write
 * 
 * \return On success, return the SBCOK, otherwise return the apporiate value 
 */
SBCStatus SBC_RawAlignedWriteBlockIO(VOID *blk, UINTN off, UINTN sz, CONST VOID *buf);



/*!
 * 
 * \brief Read arbitrary bytes to a Block I/O device
 * 
 * \author leoc (9/24/25)
 * 
 * \param blk    Pointer to EFI_BLOCK_IO_PROTOCOL
 * \param off    Byte offset from the start to media to begin reading
 * \param sz     Number of bytes to read.
 * \param buf    Source bufferw to read
 * 
 * \return On success, return the SBCOK, otherwise return the apporiate value 
 */
SBCStatus SBC_RawAlignedReadBlockIO(VOID *blk, UINTN off, UINTN sz, VOID *buf);

/**
 * @fn SBC_ProtSwLoadRawPrt
 * @brief Loads and decrypts protected software data from a raw partition.
 *
 *
 * @param[in]  handle         Pointer to the boot context (`boot_proc_t`) containing block I/O handle.
 * @param[in]  shared_secret  Pointer to the shared secret key used for AES-GCM decryption.
 * @param[out] decbuf         Buffer to store the decrypted data.
 * @param[out] rdlen          Pointer to variable that receives the length of decrypted data.
 * @param[in]  rd_ofs         Offset in the raw partition from which to begin reading.
 *
 * @return SBCStatus
 *         - SBCOK: Decryption succeeded and data loaded.
 *         - SBCENCFAIL: Decryption failed.
 *         - SBCNULLP: Null pointer or memory allocation failure.
 *         - SBCFAIL: I/O or internal error during read or decrypt.
 */
SBCStatus SBC_ProtSwLoadRawPrt(VOID *handle, UINT8 *shared_secret, UINT8 *decbuf, UINTN *rdlen, UINTN rd_ofs);

/**
 * @fn SBC_WriteFile
 * @brief Writes the user data in specified file.
 * 
 * @author leonc (10/31/25)
 * 
 * @param ImageHandle Pointer to EFH_HANDLE 
 * @param FileNames   Pointer to the File path string
 * @param out         Pointer to the buffer containing data to be
   written 
 * 
 * @return On Success, return the SBCOK, otherwise, return the
 *         apporiate value.
 */
EFI_STATUS SBC_WriteFile(EFI_HANDLE ImageHandle, CHAR16 *FileNames, LV_t *out);


/**
 * @fn SBC_FindEfiFileSystemProtocol
 * @brief Locates all handles that support the EFI Simple File System Protocol.
 *
 * This function queries the UEFI firmware to find all handles that implement the
 * `gEfiSimpleFileSystemProtocolGuid`. These handles can be used to access EFI-compatible
 * file systems such as FAT32 partitions.
 *
 * @param[out] handle Pointer to a buffer that receives the array of EFI handles.
 *                    The buffer is allocated by the UEFI boot services.
 *
 * @return UINTN
 *         - Number of handles found that support the Simple File System Protocol.
 *         - Returns 0 if no handles are found or if an error occurs.
 *
 * @note
 * - The caller must ensure that `handle` is a valid pointer to receive the handle array.
 * - The returned handle array must be freed using `FreePool()` when no longer needed.
 * - This function is typically used during boot-time file access (e.g., loading FSBL/SSBL).
 *
 * @warning
 * If the protocol is not found, the function logs an error and returns 0.
 */
UINTN SBC_FindEfiFileSystemProtocol(EFI_HANDLE **handle);


/**
 * @fn SBC_IsFlieAccess
 * @brief Checks if a specified file is accessible in the EFI file system.
 *
 * This function attempts to open a file in read mode using the EFI Simple File System Protocol.
 * It verifies whether the file exists and is readable from the given image handle.
 *
 * @param[in] ImageHandle EFI image handle used to locate the file system protocol.
 * @param[in] FileNames   Pointer to the filename (UTF-16 string) to be accessed.
 *
 * @return EFI_STATUS
 *         - EFI_SUCCESS: File was found and is accessible.
 *         - EFI_NOT_FOUND: File does not exist.
 *         - EFI_INVALID_PARAMETER: Invalid input parameters.
 *         - Other EFI error codes depending on protocol or volume access failure.
 *
 * @note
 * - The function uses `HandleProtocol` to locate the file system and attempts to open the volume and file.
 * - If the file is successfully opened, it is immediately closed and `EFI_SUCCESS` is returned.
 * - This function does not read or process the file contents.
 *
 * @warning
 * The caller must ensure that `FileNames` points to a valid null-terminated CHAR16 string.
 */
EFI_STATUS SBC_IsFlieAccess(EFI_HANDLE ImageHandle, CHAR16 *FileNames);

/**
 * @fn SBC_IsDirExist
 * @brief Checks whether a specified directory exists in the EFI file system.
 *
 * This function attempts to open a directory from the root of the EFI volume using the
 * Simple File System Protocol. If the directory exists and is valid, it returns TRUE.
 *
 * @param[in] ImageHandle    EFI image handle used to locate the file system protocol.
 * @param[in] DirectoryName  Pointer to the UTF-16 string representing the directory path.
 *
 * @return BOOLEAN
 *         - TRUE: Directory exists and is valid.
 *         - FALSE: Directory does not exist or is not accessible.
 *
 * @note
 * - The function uses `EFI_FILE_MODE_READ` and `EFI_FILE_DIRECTORY` flags to open the target directory.
 * - It verifies the directory by checking the `EFI_FILE_DIRECTORY` attribute in the file info.
 * - All opened handles are properly closed before returning.
 *
 * @warning
 * The caller must ensure that `DirectoryName` is a valid null-terminated CHAR16 string.
 * If memory allocation for file info fails, the function will return FALSE.
 */
BOOLEAN SBC_IsDirExist(EFI_HANDLE ImageHandle, CHAR16 *DirectoryName);


/**
 * @fn SBC_FindFileBufHndl
 * @brief Searches for a valid EFI handle that can access the specified file.
 *
 * This function iterates through a list of EFI handles and checks which one can successfully
 * access the file specified by `f_path`. The index of the valid handle is returned via `hndlcnt`.
 *
 * @param[in]     f_path    Pointer to the UTF-16 file path to search for.
 * @param[in,out] hndlcnt   Pointer to the number of handles to check. On success, updated with the index of the valid handle.
 * @param[in]     hndl      Pointer to an array of EFI handles to search.
 *
 * @return SBCStatus
 *         - SBCOK: A valid handle was found that can access the file.
 *         - SBCNOTFND: No handle could access the file.
 *         - SBCNULLP: Null pointer input detected.
 *
 * @note
 * - The function uses `SBC_IsFlieAccess()` to test file accessibility for each handle.
 * - On success, `*hndlcnt` is updated to the index of the first valid handle.
 * - The caller must ensure that `hndl` points to a valid array of EFI handles.
 *
 * @warning
 * The function stops at the first successful access and does not check all handles.
 */
SBCStatus  SBC_FindFileBufHndl(UINT16 *f_path, UINTN *hndlcnt, VOID **hndl);

/**
 * @fn SBC_LogWriteFile
 * @brief Appends log data to a file in the EFI file system.
 *
 * This function locates the EFI Simple File System Protocol, opens the specified file,
 * moves the file pointer to the end, and writes the contents of the provided buffer.
 *
 * @param[in]  ImageHandle EFI image handle used to locate the file system.
 * @param[in]  FileNames   Pointer to the UTF-16 string representing the target file name.
 * @param[in]  out         Pointer to an LV_t structure containing the data to be written.
 *
 * @return EFI_STATUS
 *         - EFI_SUCCESS: Data was successfully written to the file.
 *         - EFI_INVALID_PARAMETER: Input buffer is null or invalid.
 *         - EFI_NOT_FOUND / other EFI errors: File system or file access failed.
 *
 * @note
 * - The file is opened in read/write mode. If it does not exist, this function will fail unless modified to create it.
 * - The file pointer is moved to the end before writing, so this function appends data.
 * - The caller must ensure that `out->value` points to valid data and `out->length` is non-zero.
 *
 * @warning
 * This function does not perform file creation or truncation. It assumes the file already exists.
 */
EFI_STATUS SBC_LogWriteFile(EFI_HANDLE ImageHandle, CHAR16 *FileNames, LV_t *out);


/**
 * @fn SBC_LoadSystemSetting
 * @brief Loads system configuration data from a block I/O device into a memory blob.
 *
 * This function reads system settings or configuration data from a secure storage region
 * (typically a raw partition) using the provided block I/O handle, and stores the result
 * into the specified memory blob.
 *
 * @param[in]  blkio  Pointer to the block I/O interface used to access the storage device.
 * @param[out] blob   Pointer to the memory buffer where the loaded configuration will be stored.
 *
 * @return SBCStatus
 *         - SBCOK: System settings successfully loaded.
 *         - SBCNULLP: Null pointer input detected.
 *         - SBCFAIL: Read or parse operation failed.
 *         - SBCDECFAIL: Decryption of system settings failed.
 *
 * @note
 * - The caller must ensure that `blob` points to a valid memory region with sufficient size.
 * - This function may internally perform decryption or integrity checks depending on the system design.
 * - Used during boot initialization to retrieve platform configuration, security policies, or provisioning data.
 *
 * @warning
 * The function assumes that the system settings are stored in a known offset and format.
 * If the format is corrupted or the key is invalid, the operation may fail.
 */
SBCStatus SBC_LoadSystemSetting(VOID *blkio, VOID *blob);
#endif
