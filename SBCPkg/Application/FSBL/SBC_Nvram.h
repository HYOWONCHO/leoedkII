#ifndef _SBC_NVRAM_H_
#define _SBC_NVRAM_H_

#define SBC_NVRAM_MAGIC_ID      0x53424300

typedef enum {
    //
    // Reset Request
    //
    SBC_BOOT_RESET_REQ_FSBL             = SBC_NVRAM_MAGIC_ID | 0x1,
    SBC_BOOT_RESET_REQ_SSBL,
    SBC_BOOT_RESET_REQ_FACTORY,
    SBC_BOOT_RESET_REQ_NORMAL,
    SBC_BOOT_RESET_REQ_UPDATE,
    //
    // Shutdown Request
    //
    SBC_BOOT_SHDN_REQ_FSBL,
    SBC_BOOT_SHDN_REQ_SSBL,
    SBC_BOOT_SHDN_REQ_FACTORY,
    SBC_BOOT_SHDN_REQ_NORMAL,
    SBC_BOOT_SHDN_REQ_UPDATE,
#ifdef _UNIT_TEST_ON_
    //
    // Unit Test Boot Condition
    //
    SBC_BOOT_UNIT_SHDN_REQ_FSBL,
    SBC_BOOT_UNIT_SHDN_REQ_SSBL,
    SBC_BOOT_SHDN_SFR_006,
    SBC_BOOT_SHDN_SFR_003,
#endif
    SBC_BOOT_ORDER_UNKNOWN             
}sbc_boot_varible_t;


#endif
