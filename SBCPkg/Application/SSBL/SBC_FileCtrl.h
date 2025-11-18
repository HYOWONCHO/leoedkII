/********************************************************************************
 * Copyright (C) 2024 by Security Platform Inc.                                 *
 * This file is part of the SBC Project.                                        *
 *                                                                              *
 * This software contains confidential and proprietary information of           *
 * Security Platform Inc. Unauthorized reproduction, distribution, or           *
 * disclosure of this software, in whole or in part, is strictly prohibited.    *
 ********************************************************************************/

#ifndef SBC_FILECTRL_H
#define SBC_FILECTRL_H

#include "SBC_ErrorType.h"
#include <Protocol/BlockIo.h>

#define BOOT_VENDOR_BASEDIR     L"\\EFI\\rocky"

#define BOOT_MODE_FNAME         L"\\EFI\\BOOT\\bootmode"
#define BOOT_MODE_STRNRORMAL    "normal"
#define BOOT_MODE_STRUPDATE     "update"
#define BOOT_MODE_STRFACTORY    "factory"

//
// Chunk size for streaming copies (Block <-> Block, Block <-> File)
//

/**
 * @def SBC_RW_CHUNK_SZ
 * @brief Default file read/write chunk size in bytes.
 */
#define SBC_RW_CHUNK_SZ    1024        ///< 1KB chunk for block-to-block copy


/**
 * @def SBC_FILE_CHUNK_SZ
 * @brief Default file read/write chunk size in bytes.
 */
#define SBC_FILE_CHUNK_SZ  (64 * 1024) ///< 64KB chunk for file operations


/**
 * @def FILE_CHUNK_SZ
 * @brief Default file read/write chunk size in bytes.
 *
 * @see SBC_CopyFileToBlockDevice()
 * @see SBC_CopyBlockDeviceToFile()
 */
#define FILE_CHUNK_SZ   (128 * 1024)   // 128KB


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


/**
 * @def SBC_RAWPRT_DFLT_SHIFT
 * @brief Default block size shift value for raw partition operations.
 */
#define SBC_RAWPRT_DFLT_SHIFT                       0x9

/**
 * @def SBC_RAWPRT_DFLT_BLK_SZ
 * @brief Default raw partition block size (in bytes).
 */
#define SBC_RAWPRT_DFLT_BLK_SZ                      (1 << SBC_RAWPRT_DFLT_SHIFT)


/**
 * @def SBC_FILE_RW_BLK(len)
 * @brief Calculate the number of read/write blocks for a given data length.
 *
 * This macro computes how many full block units (based on
 * @ref SBC_RAWPRT_DFLT_BLK_SZ) are required to process a file of the specified
 * length @p len.  
 */
#define SBC_FILE_RW_BLK(len)                        \
    ({                                              \
        UINT32 _x = len;                            \
        if (_x <= SBC_RAWPRT_DFLT_BLK_SZ) {         \
            _x = 0;                                 \
        } else {                                    \
            _x = len / SBC_RAWPRT_DFLT_BLK_SZ;      \
        }                                           \
        _x;                                         \
    })   
/*! 
    \defgroup   RawPartition        Raw Partition related data structure and defines
    \{
*/



/**
 * @def SBC_RAW_PRTHDR_LBA
 * @brief Logical Block Address (LBA) of the raw partition header.
 *
 * Defines the starting LBA where the raw partition header is located.
 * Typically, this is set to 0 to indicate the first logical block of the device.
 */
#define SBC_RAW_PRTHDR_LBA                  0

/**
 * @def SBC_RAWPRT_MAGIC_ID
 * @brief Magic identifier for the raw partition header.
 *
 * Defines a unique 32-bit magic value (`0xAA55AA55`) used to validate
 * the presence and integrity of a raw partition header.
 */
#define SBC_RAWPRT_MAGIC_ID                 0xAA55AA55

/**
 * @def SBC_PRTNIFO_LEN
 * @brief Partition information length (in bytes).
 */
#define SBC_PRTNIFO_LEN                     64

/**
 * @def SBC_HDR_SKIP_LEN
 * @brief Number of bytes to skip before the partition header data begins.
 */
#define SBC_HDR_SKIP_LEN                    46

/**
 * @def SBC_BOOT_PRES_LEN
 * @brief Boot presence flag length (in bytes).
 */
#define SBC_BOOT_PRES_LEN                   4

/**
 * @def SBC_BOOT_MODE_LEN
 * @brief Boot mode field length (in bytes).
 */
#define SBC_BOOT_MODE_LEN                   2

/**
 * @def SBC_KEY_MODE_LEN
 * @brief Key mode field length (in bytes).
 */
#define SBC_KEY_MODE_LEN                    2

/**
 * @def SBC_RECOVERY_LEN
 * @brief Recovery flag field length (in bytes).
 */
#define SBC_RECOVERY_LEN                    2


#pragma pack(push, 1)
/*!
    \struct rawprt_hdr_t
    \brief Raw Partition Header  structure
*/
typedef struct _rawprt_hdr_t {
    UINT32      magicid;                                /**< Identifier for SBC Raw-Partition */
    UINT8       prtinfo[SBC_PRTNIFO_LEN];               /**< Partition information */
    UINT8       reserv[SBC_HDR_SKIP_LEN];
    UINT16      bootmode;                               /**< Boot Mode */   
    UINT16      keymode;                                /*! Key Mode*/
    UINT16      rcvmode;                                /*! Recover mode */     
    UINT8       bootpres[SBC_BOOT_PRES_LEN];            /**< Boot pres */
    UINT8       bootpres_reserv[SBC_BOOT_PRES_LEN];     /**< Boot pres */
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
/**
 * @union boot_fw_inf_t
 * @brief Boot firmware image information structure.
 *
 * This union represents firmware image metadata and raw image content
 * for multiple boot components including FSBL, SSBL, OS, and SW.
 */

/** @var boot_fw_inf_t::mbr
 *  @brief Member field representation of firmware image data.
 *
 *  Provides structured access to FSBL, SSBL, OS, and SW image data and lengths.
 */

/** @var boot_fw_inf_t::mbr.fsbln
 *  @brief Length of the FSBL (First Stage Boot Loader) image in bytes.
 */

/** @var boot_fw_inf_t::mbr.fsblimg
 *  @brief FSBL image data buffer of size @ref BOOT_FSBL_IMGMAX bytes.
 */

/** @var boot_fw_inf_t::mbr.ssbln
 *  @brief Length of the SSBL (Second Stage Boot Loader) image in bytes.
 */

/** @var boot_fw_inf_t::mbr.ssblimg
 *  @brief SSBL image data buffer of size @ref BOOT_SSBL_IMGMAX bytes.
 */

/** @var boot_fw_inf_t::mbr.osln
 *  @brief Length of the OS image in bytes.
 */

/** @var boot_fw_inf_t::mbr.osimg
 *  @brief OS image data buffer of size @ref BOOT_OS_IMGMAX bytes.
 */

/** @var boot_fw_inf_t::mbr.swn
 *  @brief Length of the SW (application or service layer) image in bytes.
 */

/** @var boot_fw_inf_t::mbr.swimg
 *  @brief SW image data buffer of size @ref BOOT_SW_IMGMAX bytes.
 */

/** @var boot_fw_inf_t::value
 *  @brief Raw byte array representation of the entire firmware image block.
 *
 *  Provides a contiguous view of all image data for binary serialization,
 *  hashing, or storage operations. The maximum length is defined by @ref BOOT_FW_IMGMAX.
 */
typedef union _boot_fw_inf_t {
    struct {
        UINT32 fsbln;                      /*!< Length of FSBL image. */
        UINT8  fsblimg[BOOT_FSBL_IMGMAX];  /*!< FSBL image buffer. */
        UINT32 ssbln;                      /*!< Length of SSBL image. */
        UINT8  ssblimg[BOOT_SSBL_IMGMAX];  /*!< SSBL image buffer. */
        UINT32 osln;                       /*!< Length of OS image. */
        UINT8  osimg[BOOT_OS_IMGMAX];      /*!< OS image buffer. */
        UINT32 swn;                        /*!< Length of SW image. */
        UINT8  swimg[BOOT_SW_IMGMAX];      /*!< SW image buffer. */
    } mbr;                                 /*!< Structured image metadata view. */

    UINT8 value[BOOT_FW_IMGMAX];           /*!< Raw byte array representation. */
} boot_fw_inf_t;

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
/**
 * @def SBC_RPTN_FIRST_SKIP_BYTES
 * @brief Number of bytes to skip at the beginning of the raw partition.
 */
#define SBC_RPTN_FIRST_SKIP_BYTES           0x40  /**< 64 bytes */

/**
 * @def SBC_RPTN_INFO_LEN
 * @brief Length of the partition information block (in bytes).
 */
#define SBC_RPTN_INFO_LEN                   0x40    /**< 64 bytes */

/**
 * @union sbc_rptn_header_t
 * @brief Raw Partition Header structure for SBC devices.
 */

/** @var sbc_rptn_header_t::m
 *  @brief Structured partition header view.
 *
 *  Provides separate access to the Skip and Info regions within
 *  the raw partition header.
 */

/** @var sbc_rptn_header_t::m.skip
 *  @brief Skip buffer (contains the magic ID to identify the partition).
 *
 *  This 64-byte region may include
 */
typedef union _sbc_rtpn_header_t {
    struct {
        UINT8 skip[SBC_RPTN_INFO_LEN]; /**< Skip buffer, contains magic ID. */
        UINT8 info[SBC_RPTN_INFO_LEN]; /**< Partition information region. */
    } m;                               /**< Structured header representation. */

    UINT8 value[SBC_RPTN_INFO_LEN << 1]; /**< Raw byte array view of the header. */
} sbc_rptn_header_t;

                                                                                                             
                                                                                                             
/**
 * @fn EFI_STATUS SBC_ReadFile(EFI_HANDLE ImageHandle, CHAR16 *FileNames, LV_t *out)
 * @brief Read a file from a UEFI file system into a memory buffer.
 *
 * This function locates and opens a file specified by @p FileNames using the
 * provided UEFI image handle @p ImageHandle.  
 * It reads the file contents into the buffer described by @p out, which includes
 * the pointer and length fields for the loaded data.
 *
 * @param[in]  ImageHandle  Handle to the current loaded image.  
 *                          Used to locate the EFI_SIMPLE_FILE_SYSTEM_PROTOCOL
 *                          for accessing the underlying filesystem.
 * @param[in]  FileNames    Unicode (CHAR16) string representing the full or relative
 *                          path of the file to be read (e.g., L"\\EFI\\BOOT\\bootx64.efi").
 * @param[out] out          Pointer to an @ref LV_t structure that receives the file data
 *                          and its size. The buffer is allocated internally and must be
 *                          released by the caller using FreePool().
 *
 * @retval EFI_SUCCESS      The file was successfully read into memory.
 * @retval EFI_NOT_FOUND    The specified file could not be located.
 * @retval EFI_INVALID_PARAMETER One or more parameters are invalid or NULL.
 * @retval EFI_OUT_OF_RESOURCES  Memory allocation failed while reading the file.
 * @retval EFI_DEVICE_ERROR  A device or I/O error occurred during the read operation.
 */
EFI_STATUS SBC_ReadFile(EFI_HANDLE ImageHandle, CHAR16 *FileNames, LV_t *out);
                                                                                                    
                                                                                                             
/**
 * @fn SBCStatus SBC_GetFileSize(CHAR16 *FileName, UINTN *FileSize)
 * @brief Retrieve the size of a specified file in the UEFI file system.
 *
 * @param[in]  FileName   Unicode (CHAR16) string representing the full or relative
 *                        path of the file whose size is to be determined.
 *                        Example: L"\\EFI\\BOOT\\bootx64.efi"
 * @param[out] FileSize   Pointer to a variable that receives the size of the file,
 *                        in bytes.
 *
 * @retval SBCOK          The file size was successfully retrieved.
 * @retval SBCFAIL        The file could not be found or opened.
 * @retval SBCNULLP       One or more input pointers are NULL.
 * @retval SBCIO          A device or I/O error occurred during access.
 * @retval SBCINVPARAM    Invalid file handle or parameter.
 *
 */
SBCStatus SBC_GetFileSize(CHAR16 *FileName, UINTN *FileSize);
                                             
                                                                                                             
/**
 * @fn UINTN SBC_FileSysFindHndl(EFI_HANDLE *handle)
 * @brief Locate available EFI file system handles.
 *
 * @param[out] handle   Pointer to a buffer that receives an array of EFI handles.
 *                      Each handle represents a file system that can be opened
 *                      using `EFI_SIMPLE_FILE_SYSTEM_PROTOCOL`.
 *                      The caller must allocate a buffer large enough to hold
 *                      all handles, typically using `LocateHandleBuffer()`
 *                      or dynamic allocation.
 *
 * @return
 * The number of valid file system handles found.  
 * Returns 0 if no file system handles were located or an error occurred.
 */
UINTN SBC_FileSysFindHndl(EFI_HANDLE *handle);
                                                           
                                                                                                             
/**
 * @fn SBCStatus SBC_CreateFile(EFI_HANDLE h, CHAR16 *fname)
 * @brief Create a new file in the UEFI file system.
 *
 * @param[in] h        Handle to a valid EFI file system.
 *                     Typically obtained via @ref SBC_FileSysFindHndl().
 * @param[in] fname    Unicode (CHAR16) string representing the file path
 *                     and name to be created (e.g., L"\\LOG\\bootlog.txt").
 *
 * @retval SBCOK        The file was successfully created.
 * @retval SBCFAIL      Failed to create the file due to a write or access error.
 * @retval SBCNULLP     One or more input pointers are NULL.
 * @retval SBCIO        A device or I/O error occurred while creating the file.
 * @retval SBCINVPARAM  Invalid file name or handle.
 */
SBCStatus SBC_CreateFile(EFI_HANDLE h, CHAR16 *fname);
                                                  
                                                                                                             
/**
 * @fn SBCStatus SBC_CreateDirectory(EFI_HANDLE h, CHAR16 *fname)
 * @brief Create a new directory in the UEFI file system.
 *
 * @param[in] h        Handle to a valid EFI file system.
 *                     Typically obtained via @ref SBC_FileSysFindHndl().
 * @param[in] fname    Unicode (CHAR16) string representing the file path
 *                     and name to be created (e.g., L"\\LOG\\bootlog.txt").
 *
 * @retval SBCOK        The file was successfully created.
 * @retval SBCFAIL      Failed to create the file due to a write or access error.
 * @retval SBCNULLP     One or more input pointers are NULL.
 * @retval SBCIO        A device or I/O error occurred while creating the file.
 * @retval SBCINVPARAM  Invalid file name or handle.
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
 * @retval SBCOK        The file was successfully created.
 * @retval SBCFAIL      Failed to create the file due to a write or access error.
 * @retval SBCNULLP     One or more input pointers are NULL.
 * @retval SBCIO        A device or I/O error occurred while creating the file.
 * @retval SBCINVPARAM  Invalid file name or handle.                              
 */                                                                                                          
SBCStatus SBC_ReadRawPrtHeaderInfo(VOID *blkhnd, VOID *rdbuf,  UINT32 *rdlen);
                           
                           
/**
 * @fn SBCStatus SBC_RawPrtReadBlock(VOID *blkhnd, VOID *rdbuf, UINT32 *rdlen, UINTN rlba)
 * @brief Read a raw data block from a physical storage device (LBA-based).
 *
 * @param[in]  blkhnd   Pointer to an EFI_BLOCK_IO_PROTOCOL handle or equivalent
 *                      block device handle from which to read data.
 * @param[out] rdbuf    Pointer to a buffer that receives the data read from the device.
 *                      The buffer must be large enough to hold the number of bytes specified
 *                      by @p rdlen.
 * @param[in,out] rdlen Pointer to a 32-bit variable specifying the requested read size (in bytes).
 *                      On return, it may be updated to reflect the actual number of bytes read.
 * @param[in]  rlba     Logical Block Address (LBA) on the device from which to begin reading.
 *
 * @retval SBCOK         Data was successfully read from the device.
 * @retval SBCFAIL       Read operation failed or incomplete.
 * @retval SBCNULLP      One or more input pointers are NULL.
 * @retval SBCIO         I/O or hardware access error occurred.
 * @retval SBCINVPARAM   Invalid parameter (e.g., unaligned buffer or invalid LBA).
 *
 */
SBCStatus SBC_RawPrtReadBlock(VOID *blkhnd, VOID *rdbuf, UINT32 *rdlen, UINTN rlba);
   
                      
/*!
 * \fn SBCStatus  SBC_FindBlkIoHandle(OUT VOID **hblk)
 * 
 * \brief Find the Block Protocol interface for SBC Raw Partition 
 * 
 * 
 * \param hblk   Context handle for Block IO
 * 
 * @retval SBCOK        The file was successfully created.
 * @retval SBCFAIL      Failed to create the file due to a write or access error.
 * @retval SBCNULLP     One or more input pointers are NULL.
 * @retval SBCIO        A device or I/O error occurred while creating the file.
 * @retval SBCINVPARAM  Invalid file name or handle.
 */
SBCStatus  SBC_FindBlkIoHandle(OUT VOID **hblk);  
                    
/*!
 * \fn SBCStatus  SBC_RawPrtBlockWrite(VOID *blkio, UINT8 *wrbuf, UINT32 wrlen, UINT32 wrlba)
 * 
 * \brief Write the data in Raw Partition block at the specified
   LBA
 * 
 * 
 * 
 * \param blkio  Context handle for Block IO
 * \param wrbuf  Pointer to the buffer containing data to be
   written
 * \param wrlen  Length of the data to write, in bytes.
 * \param wrlba  Logicl Block Address where the data should be
   written
 *
 * @retval SBCOK        The file was successfully created.
 * @retval SBCFAIL      Failed to create the file due to a write or access error.
 * @retval SBCNULLP     One or more input pointers are NULL.
 * @retval SBCIO        A device or I/O error occurred while creating the file.
 * @retval SBCINVPARAM  Invalid file name or handle.
 */
SBCStatus  SBC_RawPrtBlockWrite(VOID *blkio, UINT8 *wrbuf, UINT32 wrlen, UINT32 wrlba);                    


/**
 * @fn UINT32 SBC_ReadBootMode(VOID)
 * @brief (Deprecated) Read system boot mode value.
 *
 * @deprecated
 * This function is currently **not in use**.
 * Boot mode management has been replaced or integrated into
 * the secure boot initialization sequence.
 *
 * @return
 * The boot mode value (implementation-specific).  
 * Returns 0 if unused or not implemented.
 *
 */
UINT32 SBC_ReadBootMode(VOID);



/*!
 * \fn SBCStatus SBC_ProtectedSWWrite(VOID *blkio, 
                              VOID *buf, UINT32 *len, 
                              UINT32 bnkid)
 * \brief Protected SW blob write to Raw Partition
 * 
 * \
 * 
 * \param blkio  Pointer to the block I/O interface or handle.
 * \param buf    Pointer to the buffer containing data to be
   written
 * \param len    Length of the data to write, in bytes.
 * \param bnkid  Protected SW Bank Index in Raw Partition 
 * 
 * @retval SBCOK        The file was successfully created.
 * @retval SBCFAIL      Failed to create the file due to a write or access error.
 * @retval SBCNULLP     One or more input pointers are NULL.
 * @retval SBCIO        A device or I/O error occurred while creating the file.
 * @retval SBCINVPARAM  Invalid file name or handle.
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
 *
 * 
 * \param blkio  Pointer to the block I/O interface or handle.
 * \param buf    Pointer to the buffer containing data to be
   read
 * \param len    Length of the data to read, in bytes.
 * \param bnkid  Protected SW Bank Index in Raw Partition 
 * 
 * @retval SBCOK        The file was successfully created.
 * @retval SBCFAIL      Failed to create the file due to a write or access error.
 * @retval SBCNULLP     One or more input pointers are NULL.
 * @retval SBCIO        A device or I/O error occurred while creating the file.
 * @retval SBCINVPARAM  Invalid file name or handle.
 */
SBCStatus SBC_ProtectedSWRead(VOID *blkio, 
                              VOID **buf, UINT32 *len, 
                              UINT32 bnkid);


/*!
 * \fn SBCStatus SBC_RawAlignedWriteBlockIO(VOID *blk, UINTN off, UINTN sz, CONST VOID *buf);
 * \brief Write arbitrary bytes to a Block I/O device
 * 
 * \author leoc (9/24/25)
 * 
 * \param blk    Pointer to EFI_BLOCK_IO_PROTOCOL
 * \param off    Byte offset from the start to media to begin writting
 * \param sz     Number of bytes to write.
 * \param buf    Source bufferw to write
 * 
 * @retval SBCOK        The file was successfully created.
 * @retval SBCFAIL      Failed to create the file due to a write or access error.
 * @retval SBCNULLP     One or more input pointers are NULL.
 * @retval SBCIO        A device or I/O error occurred while creating the file.
 * @retval SBCINVPARAM  Invalid file name or handle.
 */
SBCStatus SBC_RawAlignedWriteBlockIO(VOID *blk, UINTN off, UINTN sz, CONST VOID *buf);



/*!
 * \fn SBCStatus SBC_RawAlignedReadBlockIO(VOID *blk, UINTN off, UINTN sz, VOID *buf)
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
 * @retval SBCOK        The file was successfully created.
 * @retval SBCFAIL      Failed to create the file due to a write or access error.
 * @retval SBCNULLP     One or more input pointers are NULL.
 * @retval SBCIO        A device or I/O error occurred while creating the file.
 * @retval SBCINVPARAM  Invalid file name or handle.
 */
SBCStatus SBC_RawAlignedReadBlockIO(VOID *blk, UINTN off, UINTN sz, VOID *buf);

/**
 * @fn SBCStatus SBC_ProtSwLoadRawPrt(VOID *handle, UINT8 *shared_secret,
 *     UINT8 *decbuf, UINTN *rdlen, UINTN rd_ofs)
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
 * @fn EFI_STATUS SBC_WriteFile(EFI_HANDLE ImageHandle,
 *     CHAR16 *FileNames, LV_t *out)
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
 * @fn UINTN SBC_FindEfiFileSystemProtocol(EFI_HANDLE **handle)
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
 * @fn EFI_STATUS SBC_IsFlieAccess(EFI_HANDLE ImageHandle, CHAR16 *FileNames)
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
 * @fn BOOLEAN SBC_IsDirExist(EFI_HANDLE ImageHandle, CHAR16 *DirectoryName)
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
 * @fn SBCStatus  SBC_FindFileBufHndl(UINT16 *f_path, UINTN *hndlcnt,
 *     VOID **hndl)
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
 * @fn EFI_STATUS SBC_LogWriteFile(EFI_HANDLE ImageHandle, CHAR16 *FileNames,
 *     LV_t *out)
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
 * @fn SBCStatus SBC_LoadSystemSetting(VOID *blkio, VOID *blob)
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


/**
 * @fn EFI_STATUS SBC_CopyFileToBlockDevice(
 *       IN CHAR16 *SrcPath,
 *       IN VOID   *_Blk,
 *       IN UINT64 ByteOffset,
 *       OUT UINT64 *BytesWritten OPTIONAL)
 * @brief Copy a file from the EFI file system into a block device region.
 *
 * @param[in]  SrcPath       Unicode path of the source file to be copied.
 * @param[in]  _Blk          Pointer to a block device handle implementing
 *                           EFI_BLOCK_IO_PROTOCOL.
 * @param[in]  ByteOffset    Starting byte offset on the block device where
 *                           the file data will be written.
 * @param[out] BytesWritten  Optional pointer that receives the number of bytes
 *                           successfully written to the block device.
 *
 * @retval EFI_SUCCESS            The file was successfully written to the block device.
 * @retval EFI_INVALID_PARAMETER  One or more parameters are NULL or invalid.
 * @retval EFI_NOT_FOUND          The source file could not be opened.
 * @retval EFI_DEVICE_ERROR       A read/write error occurred on the block device.
 * @retval EFI_OUT_OF_RESOURCES   Memory allocation failed during the operation.
 */
EFI_STATUS SBC_CopyFileToBlockDevice(IN CHAR16 *SrcPath,
                      IN VOID *_Blk,
                      IN UINT64 ByteOffset,
                      OUT UINT64 *BytesWritten OPTIONAL);



/**
 * @fn EFI_STATUS SBC_CopyBlockDeviceToFile(
 *       IN VOID   *_Blk,
 *       IN UINT64  ByteOffset,
 *       IN UINT64  DataBytes,
 *       IN CHAR16 *DstPath,
 *       OUT UINT64 *BytesRead OPTIONAL)
 * @brief Copy a block device region to a destination file.
 *
 * @param[in]  _Blk        Pointer to the block device handle
 *                         implementing the EFI_BLOCK_IO_PROTOCOL.
 * @param[in]  ByteOffset  Byte offset within the block device where copying begins.
 * @param[in]  DataBytes   Total number of bytes to copy from the block device.
 * @param[in]  DstPath     Unicode path of the destination file to be created or overwritten.
 * @param[out] BytesRead   Optional pointer that receives the number of bytes actually read
 *                         from the block device.
 *
 * @retval EFI_SUCCESS           Data successfully copied from block device to file.
 * @retval EFI_INVALID_PARAMETER One or more input parameters are invalid or NULL.
 * @retval EFI_DEVICE_ERROR      Block device I/O operation failed.
 * @retval EFI_OUT_OF_RESOURCES  Memory allocation or file creation failed.
 * @retval EFI_VOLUME_CORRUPTED  Destination file system encountered an error.
 */
EFI_STATUS SBC_CopyBlockDeviceToFile(
    IN VOID   *_Blk,
    IN UINT64  ByteOffset,
    IN UINT64  DataBytes,
    IN CHAR16 *DstPath,
    OUT UINT64 *BytesRead OPTIONAL);


/**
 * @fn EFI_STATUS SBC_CopyBlockDeviceToFileWithSize(
 *       IN VOID   *_Blk,
 *       IN UINT64  ByteOffset,
 *       IN CHAR16 *DstPath,
 *       OUT UINT64 *BytesRead OPTIONAL)
 * @brief Copy data from a block device to a file until the end of the device region.
 *
 * @param[in]  _Blk        Pointer to a block device handle implementing
 *                         EFI_BLOCK_IO_PROTOCOL.
 * @param[in]  ByteOffset  Starting byte offset within the block device.
 * @param[in]  DstPath     Unicode destination file path where the extracted
 *                         data will be written.
 * @param[out] BytesRead   Optional pointer that receives the total number of
 *                         bytes successfully read from the block device.
 *
 * @retval EFI_SUCCESS           Data successfully copied to the output file.
 * @retval EFI_INVALID_PARAMETER One or more parameters are invalid or NULL.
 * @retval EFI_DEVICE_ERROR      Block I/O read failure occurred.
 * @retval EFI_NOT_FOUND         Unable to create or open the destination file.
 * @retval EFI_OUT_OF_RESOURCES  Memory or buffer allocation failed.
 */
EFI_STATUS SBC_CopyBlockDeviceToFileWithSize(
    IN VOID   *_Blk,        /**< [in] Block device handle. */
    IN UINT64  ByteOffset,  /**< [in] Start offset in the block device. */
    IN CHAR16 *DstPath,     /**< [in] Destination file path. */
    OUT UINT64 *BytesRead   /**< [out, optional] Total bytes read. */
);


/**
 * @fn EFI_STATUS SBC_RawReadSizeFromOffset(
 *       IN  EFI_BLOCK_IO_PROTOCOL *Blk,
 *       IN  UINT64                 ByteOffset,
 *       OUT UINT32                *OutSize)
 * @brief Read a 32-bit size value from a raw block device at a given offset.
 *
 * @param[in]  Blk         Pointer to the block device (EFI_BLOCK_IO_PROTOCOL)
 *                         from which the size field will be read.
 * @param[in]  ByteOffset  Absolute byte offset within the block device where
 *                         the 32-bit size value is stored.
 * @param[out] OutSize     Pointer to a 32-bit variable that receives the size
 *                         value read from the device.
 *
 * @retval EFI_SUCCESS            The size value was successfully read.
 * @retval EFI_INVALID_PARAMETER  One or more input parameters are invalid or NULL.
 * @retval EFI_DEVICE_ERROR       A read failure occurred on the block device.
 * @retval EFI_BAD_BUFFER_SIZE    Offset or alignment is not compatible with the device.
 */
EFI_STATUS  SBC_RawReadSizeFromOffset(
    IN  EFI_BLOCK_IO_PROTOCOL *Blk,   /**< [in] Block device handle */
    IN  UINT64                 ByteOffset, /**< [in] Offset of the size field */
    OUT UINT32                *OutSize      /**< [out] Returned size value */
);

/**
 * @fn EFI_STATUS SBC_BlkWriteArbitrary(
 *       IN EFI_BLOCK_IO_PROTOCOL *Blk,
 *       IN UINT64                 Ofs,
 *       IN CONST VOID            *Buf,
 *       IN UINTN                  Len)
 * @brief Write an arbitrary-length byte buffer into a block device.
 * 
 * @param[in] Blk   Pointer to the block device implementing EFI_BLOCK_IO_PROTOCOL.
 * @param[in] Ofs   Byte offset within the block device where writing begins.
 * @param[in] Buf   Pointer to the input buffer containing data to be written.
 * @param[in] Len   Number of bytes to write from @p Buf.
 *
 * @retval EFI_SUCCESS            The buffer was successfully written to the block device.
 * @retval EFI_INVALID_PARAMETER  One or more parameters are NULL or invalid.
 * @retval EFI_BAD_BUFFER_SIZE    Offset or length is incompatible with the device geometry.
 * @retval EFI_DEVICE_ERROR       Underlying storage returned an error condition.
 * @retval EFI_OUT_OF_RESOURCES   Required working buffers could not be allocated.
 */
EFI_STATUS SBC_BlkWriteArbitrary(
    IN EFI_BLOCK_IO_PROTOCOL *Blk, /**< [in] Block device handle. */
    IN UINT64                 Ofs, /**< [in] Byte offset for writing. */
    IN CONST VOID            *Buf, /**< [in] Source data buffer. */
    IN UINTN                  Len  /**< [in] Length of data to write. */
);

/**
 * @fn EFI_STATUS SBC_DeleteFileByPath(IN CHAR16 *FilePath)
 * @brief Delete a file from the EFI file system using its Unicode path.
 *
 * @param[in] FilePath  Unicode path of the file to be deleted.  
 *                      The path must be valid and located on an accessible
 *                      EFI Simple File System volume.
 *
 * @retval EFI_SUCCESS           The file was successfully deleted.
 * @retval EFI_INVALID_PARAMETER @p FilePath is NULL or invalid.
 * @retval EFI_NOT_FOUND         The specified file does not exist.
 * @retval EFI_ACCESS_DENIED     The file cannot be deleted due to protection
 *                               or insufficient permissions.
 * @retval EFI_DEVICE_ERROR      A device I/O error occurred during deletion.
 */
EFI_STATUS SBC_DeleteFileByPath(
    IN CHAR16 *FilePath  /**< [in] Path of the file to delete */
);


/**
 * @fn EFI_STATUS SBC_CopyBlockReadAndBlockWrite(
 *       IN EFI_BLOCK_IO_PROTOCOL *Blk,
 *       IN UINT64                 SrcOffset,
 *       IN UINT64                 DstOffset,
 *       IN UINT32                *Size OPTIONAL)
 * @brief Read size field from offset 0–3 (if Size == 0) and copy that many bytes.
 *
 * Copy operation sequence:
 *  1) If Size == 0 → Read 4 bytes from offset 0 (little-endian size)
 *  2) Read Size bytes starting at @p SrcOffset
 *  3) Write Size bytes starting at @p DstOffset
 *
 * @param[in]  Blk        Block device (EFI_BLOCK_IO_PROTOCOL).
 * @param[in]  SrcOffset  Source byte offset.
 * @param[in]  DstOffset  Destination byte offset.
 * @param[in,out] Size    [in] Size to copy, OPTIONAL.
 *                        [out] If 0 on input, returns the size read from 0–3.
 *
 * @retval EFI_SUCCESS           Operation succeeded.
 * @retval EFI_INVALID_PARAMETER Null pointers or invalid device.
 * @retval EFI_DEVICE_ERROR      Device read/write failed.
 */
EFI_STATUS
SBC_CopyBlockReadAndBlockWrite(
    IN EFI_BLOCK_IO_PROTOCOL *Blk,
    IN UINT64 SrcOffset,
    IN UINT64 DstOffset,
    IN OUT UINT32 *Size OPTIONAL
);




#endif
