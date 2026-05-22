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
#include "SBC_AntiTampering.h"
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
#define SBC_HDR_SKIP_LEN                    44

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
    UINT16      prevmode;
    UINT16      bootmode;                               /**< Boot Mode */   
    UINT16      keymode;                                /*! Key Mode*/
    UINT16      rcvmode;                                /*! Recover mode */     
    UINT8       bootpres[SBC_BOOT_PRES_LEN];            /**< Boot pres */
    UINT8       bootpres_reserv[SBC_BOOT_PRES_LEN];     /**< Boot pres */
}rawprt_hdr_t;

#pragma pack(pop)

#define BOOT_BLKIO_DFTSZ                    0x00000200U

#define BOOT_FW_SRTOFS                      0x00000200U

#define BOOT_FSBL_OFS                       0x00000000U      /**< FSBL Offset */
#define BOOT_SSBL_OFS                       0x00400000U      /**< SSB Offset */
#define BOOT_OS_OFS                         0x00800000U      /**< Operating System Offset */
#define BOOT_SW_OFS                         0x01C00000U      /**< Boot Software offset */


#define BOOT_SECTOR1_OFS                    (0x00000000U | BOOT_FW_SRTOFS)
#define BOOT_SECTOR2_OFS                    (0x08000000U | BOOT_FW_SRTOFS)
#define BOOT_SECTOR3_OFS                    (0x10000000U | BOOT_FW_SRTOFS)

#define BOOT_IMG_LENB                       0x00000004U
#define BOOT_FSBL_MAX                       0x00400000U      /**< 4M */
#define BOOT_FSBL_IMGMAX                    (BOOT_FSBL_MAX - BOOT_IMG_LENB)


#define BOOT_SSBL_MAX                       0x00400000U      /**< 4M */
#define BOOT_SSBL_IMGMAX                    (BOOT_SSBL_MAX - BOOT_IMG_LENB)


#define BOOT_OS_IMG_MB                      20U
#define BOOT_OS_MAX                         (BOOT_OS_IMG_MB << 20)      /**< 20 M */
#define BOOT_OS_IMGMAX                      (BOOT_OS_MAX - BOOT_IMG_LENB)

#define BOOT_SW_IMG_MB                      100U
#define BOOT_SW_MAX                         (BOOT_SW_IMG_MB << 20)      /**<  100 M */
#define BOOT_SW_IMGMAX                      (BOOT_SW_MAX - BOOT_IMG_LENB)


#define BOOT_FW_IMG_MB                      128U
#define BOOT_FW_IMGMAX                      (BOOT_FW_IMG_MB << 20)

/*! \brief Addresss of Protected Software    */
#define BOOT_FW_PROT_SW_POS                 (0x01C00000U | BOOT_FW_SRTOFS)


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
   
                      
                   
/**
 * @fn SBC_RawPrtBlockWrite
 * @brief Write a block-aligned buffer to raw partition using EFI Block I/O.
 *
 * This function writes @p wrbuf to the device using EFI_BLOCK_IO_PROTOCOL::WriteBlocks().
 * The caller should provide a length that is aligned to the device block size.
 *
 * @param[in] blkio
 *      Pointer to EFI_BLOCK_IO_PROTOCOL instance (Block I/O handle).
 *
 * @param[in] wrbuf
 *      Pointer to write buffer.
 *
 * @param[in] wrlen
 *      Write length in bytes. Should be non-zero and typically aligned to BlockSize.
 *
 * @param[in] wrlba
 *      Starting LBA to write.
 *
 * @retval SBCOK
 *      Write succeeded.
 *
 * @retval SBCNULLP
 *      Invalid parameter (NULL pointers).
 *
 * @retval SBCZEROL
 *      Invalid length (wrlen == 0).
 *
 * @retval SBCIO
 *      Block I/O write failure (WriteBlocks returned EFI error).
 *
 * @details
 * Processing steps:
 *
 * Step 1. Validate input parameters:
 *         - <code>blkio</code> must not be NULL
 *         - <code>wrbuf</code> must not be NULL
 *         - <code>wrlen</code> must be non-zero
 *
 * Step 2. Cast <code>blkio</code> to <code>EFI_BLOCK_IO_PROTOCOL*</code>.
 *
 * Step 3. Call <code>p->WriteBlocks()</code> with:
 *         - MediaId from <code>p->Media->MediaId</code>
 *         - LBA = <code>wrlba</code>
 *         - BufferSize = <code>wrlen</code>
 *         - Buffer = <code>wrbuf</code>
 *
 * Step 4. If WriteBlocks fails:
 *         - Print debug message and system log
 *         - Return <code>SBCIO</code>
 *
 * Step 5. Return <code>SBCOK</code> on success.
 *
 * @note
 * - Current implementation validates <code>p</code> before it is assigned:
 *   <code>p</code> is initialized to NULL, so the condition
 *   <code>((p != NULL) || (wrbuf != NULL))</code> effectively only checks <code>wrbuf</code>.
 *   Consider changing it to:
 *   <code>(blkio != NULL) && (wrbuf != NULL)</code>.
 * - Consider enforcing <code>(wrlen % p->Media->BlockSize) == 0</code> to avoid EFI_INVALID_PARAMETER.
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



/**
 * @fn SBC_RawAlignedWriteBlockIO
 * @brief Write arbitrary-length data to Block I/O at byte offset, handling unaligned head/tail via RMW.
 *
 * This function writes @p sz bytes from @p buf to the Block I/O device @p blk
 * starting at byte offset @p off. If the write is not block-aligned, it performs
 * read-modify-write (RMW) for the partial head/tail blocks, and uses direct
 * block writes for the fully-aligned body.
 *
 * @param[in] blk
 *      Pointer to EFI_BLOCK_IO_PROTOCOL instance.
 *
 * @param[in] off
 *      Byte offset from the start of the device.
 *
 * @param[in] sz
 *      Number of bytes to write.
 *
 * @param[in] buf
 *      Source buffer containing data to write.
 *
 * @retval SBCOK
 *      Write succeeded.
 *
 * @retval SBCIO
 *      Media not present or Block I/O read/write failure.
 *
 * @retval SBCINVPARAM
 *      Invalid parameter (write range exceeds device boundary).
 *
 * @retval SBCNULLP
 *      Temporary buffer allocation failed.
 *
 * @details
 * Processing steps:
 *
 * Step 1. Cast @p blk to <code>EFI_BLOCK_IO_PROTOCOL*</code> and obtain media info (<code>io->Media</code>).
 *
 * Step 2. Validate media state:
 *         - <code>MediaPresent</code> must be TRUE.
 *         - Determine block size <code>B = BlockSize</code>.
 *
 * Step 3. Compute device total size in bytes:
 *         <code>total = (LastBlock + 1) * BlockSize</code>.
 *
 * Step 4. Validate boundary:
 *         - Ensure <code>off</code> and <code>off + sz</code> do not exceed <code>total</code>.
 *         - If invalid, return <code>SBCINVPARAM</code>.
 *
 * Step 5. Initialize cursor:
 *         - <code>cur = off</code>, <code>p = (UINT8*)buf</code>
 *         - Compute starting <code>lba = cur / B</code> and intra-block offset <code>intra = cur % B</code>.
 *
 * Step 6. Head handling (partial first block):
 *         - If <code>intra != 0</code>:
 *           <ol>
 *             <li>Allocate temp block buffer (<code>tmp</code>, size B).</li>
 *             <li>Read existing block at <code>lba</code> into <code>tmp</code>.</li>
 *             <li>Copy <code>c = min(sz, B - intra)</code> bytes from <code>p</code> into <code>tmp + intra</code>.</li>
 *             <li>Write the full block <code>tmp</code> back to <code>lba</code>.</li>
 *             <li>Advance <code>p</code>, decrease <code>sz</code>, advance <code>cur</code>, increment <code>lba</code>.</li>
 *           </ol>
 *
 * Step 7. Body handling (full blocks):
 *         - While <code>sz >= B</code>:
 *           - Write one full block directly from <code>p</code> to current <code>lba</code>.
 *           - Advance pointers/counters by B and increment <code>lba</code>.
 *
 * Step 8. Tail handling (partial last block):
 *         - If remaining <code>sz > 0</code>:
 *           <ol>
 *             <li>Allocate temp block buffer (<code>tmp</code>, size B).</li>
 *             <li>Read existing block at <code>lba</code> into <code>tmp</code>.</li>
 *             <li>Overwrite the first <code>sz</code> bytes of <code>tmp</code> with remaining data from <code>p</code>.</li>
 *             <li>Write the full block <code>tmp</code> back to <code>lba</code>.</li>
 *           </ol>
 *
 * Step 9. Return <code>SBCOK</code> on success.
 *
 * @note
 * - This routine relies on RMW for unaligned writes; it preserves bytes outside the written range
 *   within the head/tail blocks.
 * - Consider validating <code>buf</code> is not NULL when <code>sz > 0</code>.
 * - Current implementation checks <code>EFI_ERROR(retval)</code> at <code>errdone</code>, but
 *   <code>retval</code> may be uninitialized on some early error paths (e.g., boundary failure).
 *   Initializing <code>retval = EFI_SUCCESS</code> at function entry would harden the code.
 * - Consider checking <code>m->ReadOnly</code> to fail early if the medium is write-protected.
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
 * @fn cf
 * @brief Load system setting repository from raw partition into an LV_t blob.
 *
 * This function allocates a block-size-aligned buffer, reads the system setting
 * repository region from raw partition starting at <code>SYS_CONF_START_OFS</code>,
 * and returns the loaded data via an <code>LV_t</code> container.
 *
 * @param[in]  blkio
 *      Pointer to EFI_BLOCK_IO_PROTOCOL (raw partition Block I/O handle).
 *
 * @param[out] blob
 *      Pointer to an <code>LV_t</code> structure that will receive:
 *      - value  : allocated buffer containing loaded system setting data
 *      - length : number of bytes read (aligned length)
 *
 * @retval SBCOK
 *      Load succeeded.
 *
 * @retval SBCNULLP
 *      Memory allocation failed (or invalid pointer in hardened implementations).
 *
 * @retval Others
 *      Propagated SBCStatus from <code>SBC_RawPrtReadBlock()</code>.
 *
 * @details
 * Processing steps:
 *
 * Step 1. Compute base LBA of system setting repository:
 *         <code>lba = SYS_CONF_START_OFS >> SBC_RAWPRT_DFLT_SHIFT</code>.
 *
 * Step 2. Compute aligned load length:
 *         <code>ldlen = ALIGN_VALUE(SYS_SETTING_STORAGE_LEN, BlockSize)</code>,
 *         where BlockSize is taken from <code>((EFI_BLOCK_IO_PROTOCOL*)blkio)->Media->BlockSize</code>.
 *
 * Step 3. Allocate a zero-initialized buffer of size <code>ldlen</code> and assign it to
 *         <code>((LV_t*)blob)->value</code>.
 *         If allocation fails, return <code>SBCNULLP</code>.
 *
 * Step 4. Read repository blocks from raw partition into the allocated buffer using
 *         <code>SBC_RawPrtReadBlock(blkio, value, &ldlen, lba)</code>.
 *         If read fails, return the error status.
 *
 * Step 5. Set <code>((LV_t*)blob)->length = ldlen</code> and return <code>SBCOK</code>.
 *
 * @note
 * - Caller is responsible for freeing <code>((LV_t*)blob)->value</code> with <code>FreePool()</code>.
 * - Consider validating <code>blkio</code> and <code>blob</code> are not NULL before use.
 * - On read failure, current implementation does not free the allocated buffer; consider freeing
 *   it and resetting <code>blob->value/length</code> in the error path to avoid leaks.
 */
SBCStatus SBC_LoadSystemSetting(VOID *blkio, VOID *blob);


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

/**
 * @fn EFI_STATUS SBC_BlkReadArbitrary(
 *       IN  EFI_BLOCK_IO_PROTOCOL *Blk,
 *       IN  UINT64                 ByteOffset,
 *       OUT VOID                  *Buffer,
 *       IN  UINTN                  Length)
 * @brief Read an arbitrary byte range from a block device, handling
 *        unaligned offsets and partial-block boundaries.
 *
 * @param[in]  Blk         Pointer to the target block device implementing
 *                         EFI_BLOCK_IO_PROTOCOL.
 * @param[in]  ByteOffset  Byte-granular offset from which data is read.
 * @param[out] Buffer      Caller-provided output buffer that receives the data.
 * @param[in]  Length      Number of bytes to read into @p Buffer.
 *
 * @retval EFI_SUCCESS            The requested region was read successfully.
 * @retval EFI_INVALID_PARAMETER  One or more parameters are NULL or invalid.
 * @retval EFI_BAD_BUFFER_SIZE    Underlying device cannot support the read
 *                                because of alignment or geometry constraints.
 * @retval EFI_DEVICE_ERROR       A block device I/O error occurred.
 *
 */
EFI_STATUS
SBC_BlkReadArbitrary(
    IN  EFI_BLOCK_IO_PROTOCOL *Blk,   /**< [in] Block I/O device handle */
    IN  UINT64                 ByteOffset, /**< [in] Arbitrary read offset */
    OUT VOID                  *Buffer,  /**< [out] Output buffer for data */
    IN  UINTN                  Length   /**< [in] Number of bytes to read */
);

/**
 * @fn SBC_BaseAnswerExtractFromDisk
 * @brief Extract Base Answer data from raw system configuration partition.
 *
 * This function reads the system configuration storage region from disk and
 * extracts Base Answer fields from the reserved response offset area.
 *
 * @param[in]  blkio
 *      Block I/O protocol handle for raw partition access.
 *
 * @param[out] p
 *      Pointer to base_ansid_t structure to receive:
 *      - msglen : encrypted message length
 *      - encmsg : encrypted message payload
 *      - iv     : AES-GCM IV
 *      - tag    : AES-GCM authentication tag
 *
 * @retval SBCOK
 *      Extraction succeeded.
 *
 * @retval SBCNULLP
 *      Invalid parameter or allocation failure.
 *
 * @retval SBCFAIL
 *      Forced failure in test mode or underlying read error.
 *
 * @retval SBCBSANSWNOTFND
 *      Base Answer not found (msglen <= 0).
 *
 * @details
 * Processing steps:
 *
 * Step 1. Validate output parameter (<code>p</code> != NULL).
 *
 * Step 2. Calculate the base LBA of the system configuration storage
 *         using <code>SYS_CONF_START_OFS</code>.
 *
 * Step 3. Align the storage length to the block size reported by
 *         <code>EFI_BLOCK_IO_PROTOCOL</code>.
 *
 * Step 4. Allocate a zero-initialized temporary buffer for the read operation.
 *
 * Step 5. Read the system configuration data block from the raw partition
 *         into the temporary buffer.
 *
 * Step 6. Set <code>offset</code> to the reserved response offset
 *         (<code>SYS_CONF_RES_OFS</code>).
 *
 * Step 7. Extract Base Answer message length (<code>msglen</code>) from the buffer
 *         and validate it is greater than 0. If not, return <code>SBCBSANSWNOTFND</code>.
 *
 * Step 8. Extract encrypted message (<code>encmsg</code>) using <code>msglen</code>.
 *
 * Step 9. Extract AES-GCM IV (<code>iv</code>) with length <code>BASE_ANS_IV_KEY_STR</code>.
 *
 * Step 10. Extract AES-GCM authentication tag (<code>tag</code>) with length
 *          <code>BASE_ANS_TAG_LEN</code>.
 *
 * Step 11. Return status (caller owns <code>p</code> and must ensure its internal
 *          buffers are large enough).
 *
 * @note
 * - Caller must ensure <code>p->encmsg</code> buffer capacity is >= stored msglen.
 * - This function currently does not FreePool(loadbuf); consider releasing it
 *   to avoid memory leaks in long-running contexts.
 */
SBCStatus SBC_BaseAnswerExtractFromDisk(VOID *blkio, base_ansid_t *p);

/**
 * @fn SBC_EFI_FSBL_Load
 * @brief Load FSBL (or test image) from the EFI System Partition into memory.
 *
 * This function loads a target EFI binary from the same filesystem device
 * where the current image is loaded (typically ESP). The loaded content is
 * returned via @p lv (buffer pointer + length).
 *
 * Target file selection:
 * - Normal build: "\\EFI\\BOOT\\bootx64.efi"
 * - _SSBL_TEST_RUN_ build: "\\EFI\\BOOT\\FSBL.efi"
 *
 * @param[in,out] lv
 *      Pointer to LV_t output container.
 *      On success:
 *        - lv->value  points to newly allocated buffer containing file content
 *        - lv->length is set to file size in bytes
 *      On failure:
 *        - lv->value is NULL
 *        - lv->length is 0
 *
 * @retval EFI_SUCCESS
 *      File loaded successfully.
 *
 * @retval EFI_INVALID_PARAMETER
 *      @p lv is NULL.
 *
 * @retval EFI_OUT_OF_RESOURCES
 *      Memory allocation failed.
 *
 * @retval EFI_NOT_FOUND
 *      Failed to resolve LoadedImage protocol or filesystem device handle.
 *
 * @retval Others
 *      Propagated EFI_STATUS from underlying filesystem operations.
 *
 * @details
 * Processing steps:
 *
 * Step 1. Validate input parameter (<code>lv</code> != NULL). If invalid, return
 *         <code>EFI_INVALID_PARAMETER</code>.
 *
 * Step 2. Select the target file path depending on build option
 *         (<code>_SSBL_TEST_RUN_</code>).
 *
 * Step 3. Initialize output fields:
 *         <code>lv->value = NULL</code>, <code>lv->length = 0</code>.
 *
 * Step 4. Query the target file size using <code>GetFileSizeOnMyFs()</code>.
 *         If it fails, return the error status.
 *
 * Step 5. Allocate a buffer of <code>FileSize</code> bytes and set
 *         <code>lv->length = FileSize</code>. If allocation fails, return
 *         <code>EFI_OUT_OF_RESOURCES</code>.
 *
 * Step 6. Resolve <code>EFI_LOADED_IMAGE_PROTOCOL</code> from <code>gImageHandle</code>
 *         to obtain the filesystem device handle (<code>LoadedImage->DeviceHandle</code>).
 *         If not found, free the buffer, reset <code>lv</code>, and return
 *         <code>EFI_NOT_FOUND</code>.
 *
 * Step 7. Read the file content using the existing <code>SBC_ReadFile()</code>
 *         by passing <code>LoadedImage->DeviceHandle</code> (a handle that supports
 *         SimpleFS) and <code>TargetPath</code>.
 *         If read fails, free the buffer, reset <code>lv</code>, and return the error.
 *
 * Step 8. Return <code>EFI_SUCCESS</code> with <code>lv</code> containing the loaded image.
 *
 * @note
 * - The caller is responsible for freeing <code>lv->value</code> with <code>FreePool()</code>.
 * - This function intentionally passes <code>LoadedImage->DeviceHandle</code> to
 *   <code>SBC_ReadFile()</code> because <code>gImageHandle</code> usually does not have
 *   SimpleFS installed.
 */
EFI_STATUS
SBC_EFI_FSBL_Load(LV_t *lv);

/**
 * @fn SBC_EFI_SSBL_Load
 * @brief Locate and load the SSBL EFI image from an accessible EFI filesystem into memory.
 *
 * This function finds an EFI SimpleFS handle that can access the SSBL image
 * located at <code>EFI_BOOT_SSBL_PATH</code>, allocates a buffer sized to the
 * file, and loads the file content into @p lv.
 *
 * @param[in]  ImageHandle
 *      Current image handle (reserved for future use; not used in current implementation).
 *
 * @param[in,out] lv
 *      Pointer to LV_t output container.
 *      On success:
 *        - lv->value  points to newly allocated buffer containing SSBL image
 *        - lv->length is set to SSBL image size in bytes
 *
 * @retval SBCOK
 *      SSBL loaded successfully.
 *
 * @retval SBCFAIL
 *      Failed to find an EFI filesystem handle that can access the SSBL file, or other fatal error.
 *
 * @retval SBCNULLP
 *      Memory allocation failed.
 *
 * @retval SBCNOTFND
 *      SSBL file access succeeded, but read operation failed.
 *
 * @retval Others
 *      Propagated SBCStatus from SBC_GetFileSize() or internal validations.
 *
 * @details
 * Processing steps:
 *
 * Step 1. Query SSBL file size using <code>SBC_GetFileSize(EFI_BOOT_SSBL_PATH)</code>.
 *         If not found or error occurs, return the error status.
 *
 * Step 2. Enumerate EFI filesystem handles via <code>SBC_FindEfiFileSystemProtocol()</code>.
 *         If none are found, return <code>SBCFAIL</code>.
 *
 * Step 3. Iterate over filesystem handles and check accessibility of
 *         <code>EFI_BOOT_SSBL_PATH</code> via <code>SBC_IsFlieAccess()</code>.
 *         Stop at the first handle that can access the file.
 *
 * Step 4. If no filesystem handle can access the SSBL file, return <code>SBCFAIL</code>.
 *
 * Step 5. Allocate a zero-initialized buffer of <code>len_of_kernel</code> bytes,
 *         assign it to <code>lv->value</code>, and set <code>lv->length</code>.
 *
 * Step 6. Read the SSBL file content using <code>SBC_ReadFile()</code> with the selected
 *         filesystem handle.
 *         If read fails, set <code>ret = SBCNOTFND</code> and return.
 *
 * Step 7. Return <code>SBCOK</code> on success.
 *
 * @note
 * - The caller is responsible for freeing <code>lv->value</code> with <code>FreePool()</code>.
 * - Consider validating <code>lv</code> is not NULL before use.
 * - Consider initializing <code>Status</code> before the loop to avoid using an
 *   uninitialized value if the loop does not find a valid handle.
 * - If <code>SBC_FindEfiFileSystemProtocol()</code> allocates <code>hndl</code>,
 *   define ownership and free it accordingly to avoid leaks.
 */
SBCStatus SBC_EFI_SSBL_Load(EFI_HANDLE ImageHandle, LV_t *lv);

/**
 * @fn SBC_EFI_Kernel_Load
 * @brief Locate and load the Linux kernel image from an accessible EFI filesystem into memory.
 *
 * This function resolves the kernel path, finds an EFI SimpleFS handle that can
 * access the kernel file, allocates a buffer sized to the kernel image, and
 * loads the file content into @p lv.
 *
 * @param[in]  ImageHandle
 *      Current image handle (reserved for future use; not used in current implementation).
 *
 * @param[in,out] lv
 *      Pointer to LV_t output container.
 *      On success:
 *        - lv->value  points to newly allocated buffer containing the kernel image
 *        - lv->length is set to the kernel image size in bytes
 *      On failure:
 *        - lv->value may be NULL (or stale if caller didn't pre-init); caller should initialize it.
 *
 * @retval SBCOK
 *      Kernel loaded successfully.
 *
 * @retval SBCFAIL
 *      Failed to find a filesystem handle that can access the kernel, or other fatal error.
 *
 * @retval SBCNULLP
 *      Memory allocation failed.
 *
 * @retval SBCNOTFND
 *      Kernel file exists but read operation failed.
 *
 * @retval Others
 *      Propagated SBCStatus from SBC_GetFileSize() or internal validations.
 *
 * @details
 * Processing steps:
 *
 * Step 1. Resolve the kernel path by calling <code>_find_kernel_path()</code>
 *         which sets <code>kernel_name</code> and (optionally) <code>len_of_kernel</code>.
 *
 * Step 2. Query the kernel file size using <code>SBC_GetFileSize()</code>.
 *         If the file is not found or size query fails, return the error.
 *
 * Step 3. Enumerate EFI filesystem handles via <code>SBC_FindEfiFileSystemProtocol()</code>.
 *         If none are found, return <code>SBCFAIL</code>.
 *
 * Step 4. Iterate over filesystem handles and test accessibility using
 *         <code>SBC_IsFlieAccess()</code>. Stop at the first handle that can access
 *         <code>kernel_name</code>.
 *
 * Step 5. If no handle can access the file, return <code>SBCFAIL</code>.
 *
 * Step 6. Allocate a zero-initialized buffer of <code>len_of_kernel</code> bytes,
 *         assign it to <code>lv->value</code>, and set <code>lv->length</code>.
 *
 * Step 7. Read the kernel file using <code>SBC_ReadFile()</code> with the selected
 *         filesystem handle. On read failure, set <code>ret = SBCNOTFND</code> and return.
 *
 * Step 8. Return <code>SBCOK</code> on success.
 *
 * @note
 * - The caller is responsible for freeing <code>lv->value</code> with <code>FreePool()</code>.
 * - Current implementation does not free <code>kernel_name</code> (if dynamically allocated)
 *   and does not free <code>hndl</code> (if allocated by SBC_FindEfiFileSystemProtocol()).
 *   Ensure ownership rules are defined to avoid leaks.
 * - Consider initializing <code>Status</code> before the loop to avoid using an
 *   uninitialized value if <code>hndlcnt</code> is 0 or loop does not execute.
 */
SBCStatus SBC_EFI_Kernel_Load(EFI_HANDLE ImageHandle, LV_t *lv);

#endif
