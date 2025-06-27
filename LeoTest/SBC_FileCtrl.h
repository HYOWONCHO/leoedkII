#ifndef SBC_FILECTRL_H
#define SBC_FILECTRL_H

#include "SBC_ErrorType.h"

#define BOOT_MODE_FNAME         L"\\EFI\\BOOT\\bootmode"
#define BOOT_MODE_STRNRORMAL    "normal"
#define BOOT_MODE_STRUPDATE     "update"
#define BOOT_MODE_STRFACTORY    "factory"

typedef enum _t_boot_mode {
    BOOT_MODE_NORMAL =  0,          /// Normal Boot Mode
    BOOT_MODE_UPDATE,               /// Image update
    BOOT_MODE_FACTORY,              /// Factory mode boot 
    BOOT_MODE_UNKNOWN
}boot_mode_t;

typedef struct _t_bm_lookup_table {
    CHAR8 *key;
    UINT32 val;
}bm_lookup_table_t;



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
#define SBC_HDR_SKIP_LEN                    52

/*! Boot pres length */
#define SBC_BOOT_PRES_LEN                   8

#pragma pack(1)
/*!
    \brief Raw Partition Header  structure
*/
typedef struct _rawprt_hdr_t {
    UINT32      magicid;                        /**< Identifier for SBC Raw-Partition */
    UINT8       prtinfo[SBC_PRTNIFO_LEN];       /**< Partition information */
    UINT8       reserv[SBC_HDR_SKIP_LEN];
    UINT8       bootpres[SBC_BOOT_PRES_LEN];    /**< Boot pres */
}rawprt_hdr_t;

#pragma pack()

#define BOOT_FW_SRTOFS                      0x00000200

#define BOOT_FSBL_OFS                       0x00000000      /**< FSBL Offset */
#define BOOT_SSB_OFS                        0x00400000      /**< SSB Offset */
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


#define BOOT_FW_LBA_BLOCKS                  (BOOT_FW_IMGMAX / SBC_RAWPRT_BLK_SZ)


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
        UINT8   swimg[BOOT_OS_IMGMAX];
    }mbr;

    UINT8 value[BOOT_FW_IMGMAX];

}boot_fw_inf_t;

#pragma pack()


#define SYS_CONF_START_OFS              0x18000000
#define SYS_CONF_OSID_OFS               0x00000000
#define SYS_CONF_RES_OFS                0x00000040          /**< Reference offset */
#define SYS_CONF_ROOT_CA_OFS            0x00000080
#define SYS_CONF_DEVID_CRT_OFS          0x00000880
#define SYS_CONF_SWID_CRT_OFS           0x00001080
#define SYS_CONF_OSID_CRT_OFS           0x00001880
#define SYS_CONF_SW_LIST_OFS            0x00002080


#define SYS_OSID_LEN                    4
#define SYS_OSID_KEY_LEN                32
#define SYS_OSID_IV_LEN                 12
#define SYS_OSID_TAG_LEN                16

#define SYS_PRES_LEN                    4
#define SYS_PRES_RES_LEN                16
#define SYS_PRES_IV_LEN                 12
#define SYS_PRES_TAG_LEN                16
#define SYS_PRES_RESERVED               16

#define SYS_PRES_INFO_MAX               (SYS_PRES_LEN + SYS_PRES_RES_LEN + SYS_PRES_IV_LEN + SYS_PRES_TAG_LEN + SYS_PRES_RESERVED)

#define SYS_CERT_LEN                    (2<<10)
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


/*!
 * \fn UINT32  SBC_ReadBootMode(VOID)
 * 
 * \author leoc (6/17/25)
 * 
 * \param void   
 * 
 * \return UINT32 
 */
UINT32  SBC_ReadBootMode(VOID);

EFI_STATUS SBC_WriteFile(EFI_HANDLE ImageHandle, CHAR16 *FileNames, LV_t *out);

UINTN SBC_FindEfiFileSystemProtocol(EFI_HANDLE **handle);
#endif
