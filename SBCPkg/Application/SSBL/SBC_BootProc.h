/********************************************************************************
 * Copyright (C) 2024 by Security Platform Inc.                                 *
 * This file is part of the SBC Project.                                        *
 *                                                                              *
 * This software contains confidential and proprietary information of           *
 * Security Platform Inc. Unauthorized reproduction, distribution, or           *
 * disclosure of this software, in whole or in part, is strictly prohibited.    *
 ********************************************************************************/


#ifndef __SBC_BOOT_PROC_H__
#define __SBC_BOOT_PROC_H__



//1f3f7e80-bd6b-4d83-93fa-9e614c313d3a

#define SB_PROC_ST_MAGICID              0xABCD0000

/**
 * @enum boot_st_t
 * @brief Represents the status of the secure boot process.
 *
 * This enumeration defines the possible states of the secure boot process.
 */
typedef enum _boot_st_t {
    SB_PROC_ST_NRMA   = SB_PROC_ST_MAGICID | 0, /**< Secure Boot Process Status: Normal  */
    SB_PROC_ST_ABNRAM,                          /**< Secure Boot Process Status: Abnormal*/
    SB_PROC_ST_UNKNOWN                          /**< Secure Boot Process Status: Unknown */
} boot_st_t;

/**
 * @def SBC_RESTORE_MAGIC_ID
 * @brief Magic identifier used for marking restore or recovery operations.
 */
#define SBC_RESTORE_MAGIC_ID               (0xA1000000)

/**
 * @def SBC_RESTORE_NOT_NEED
 * @brief Indicates that no restore operation is required.
 *
 */
#define SBC_RESTORE_NOT_NEED               (0x00000000) 

/**
 * @def SBC_RESTORE_FROM_UPDATE
 * @brief Indicates that restore operation is triggered due to a firmware update.
 */
#define SBC_RESTORE_FROM_UPDATE            (SBC_RECOVERY_MAGIC_ID | 0x01)

/**
 * @def SBC_RESTORE_FROM_RCEOVREY
 * @brief Indicates that restore operation was triggered by explicit recovery mode.
 */
#define SBC_RESTORE_FROM_RECOVERY          (SBC_RECOVERY_MAGIC_ID | 0x02)

#pragma pack(1)
/**
 * @struct boot_proc_t
 * @brief Represents the context and state of the secure boot process.
 *
 * This structure holds all necessary handles, boot parameters, and metadata
 * used during the secure boot process, including firmware bank information,
 * boot and key modes, and recovery status.
 */
typedef struct _boot_proc_t {
    VOID   *ldhndl;             /**< Load handle (e.g., image handle or context). */
    VOID   *blkhnd;             /**< Block I/O handle for accessing storage. */
    VOID   *rawprt_hdr;         /**< Pointer to raw partition header structure. */
    VOID   *baseansr;           /**< Pointer to base answer data */
    VOID   *keyinfo;            /**< Pointer to key information (e.g., atp_ident_t structure). */
    VOID   *diceid;             /**< Pointer to DICE ID*/
    UINTN   pvs_sw_bnk;         /**< Previously selected software bank ID. */
    UINTN   curr_sw_bnk;        /**< Currently selected software bank ID. */
    UINT16  bm;                 /**< Boot mode (e.g., normal, recovery, factory). */
    UINT16  km;                 /**< Key mode  */
    UINT32  bootst;             /**< Boot status (see @ref boot_st_t). */
    UINTN   rcvmode;            /**< Indicates if firmware booted from recovery mode. */
    UINTN   use_retore_fw;      /**< In Update Boot Mode, Decide whether to restore the firmware */

} boot_proc_t;
#pragma pack()

#endif
