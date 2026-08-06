#include <Uefi.h>
#include <Library/PcdLib.h>
#include <Library/UefiLib.h>
#include <Library/UefiApplicationEntryPoint.h>
//#include <Libray/RngLib.h>

#include <Library/BaseLib.h>
//#include <Library/CtLibSuppot.h>
#include <Library/BaseCryptLib.h>
#include <Library/BaseMemoryLib.h>
#include <malloc.h>
#include <Register/Intel/Cpuid.h>

#include <Library/ShellLib.h>
#include <Library/MemoryAllocationLib.h>
#include <Protocol/Smbios.h>

#include <Library/DevicePathLib.h>
#include <string.h>
#include <stdio.h>
#include <stdlib.h>

// Block Io
#include <Protocol/BlockIo.h>
#include <Protocol/DiskInfo.h>
#include <Protocol/SerialIo.h>
// Serial 
#include <Library/SerialPortLib.h>
#include <Library/PcdLib.h>
#include "leo_test.h"
// Length value


#include <Library/UefiBootServicesTableLib.h>
#include <Library/FileHandleLib.h>

#include <Protocol/Smbios.h>

#include <Library/UnitTestLib.h>

#include <Library/UefiBootManagerLib.h>


#include <openssl/objects.h>
#include <openssl/bn.h>
#include <openssl/ec.h>
#include <stdarg.h>

#include "SBC_Log.h"
#include "SBC_ErrorType.h"
#include "SBC_CryptAES.h"
#include "SBC_FileCtrl.h"
#include "SBC_TypeDefs.h"
#include "SBC_EccSignVerify.h"
#include "SBC_Config.h"
#include "SBC_AntiTampering.h"
#include "SBC_Util.h"
#include "SBC_BootProc.h"
#include "SBC_SystemControl.h"
#include "SBC_ProtectedSW.h"
#include "SBC_Hashing.h"
#include "SBC_Nvram.h"

UINTN boot_order_mode = 0ULL;
CHAR16 *sec_upt_name = L"SBCSECUREUPDATE_UC";
extern CHAR16 mrgmsg[8192];

extern SBCStatus SBC_GRUB_LoadAndStart(EFI_HANDLE ImageHandle);
extern SBCStatus SBC_BootKeyModeChange(UINT32 newbm, UINT32 newkey, VOID *priv);

SBCStatus UC_BootFWTamperingCheck(VOID *handle)
{
    SBCStatus ret = SBCOK;
    boot_proc_t *p = (boot_proc_t *)handle;
    LV_t baseansr;
    UINT8 buf[1024] = {0, };
    UINTN  varsz =  0;
    UINTN  set_order = 0;
    //EFI_STATUS retval = EFI_SUCCESS;

    

    _ucprint("*** Boot Firwmare Tampering Check \n");
    ret = SBC_SSBL_Verify(p->blkhnd, &baseansr, p->curr_sw_bnk);
    if(ret != SBCOK) {
        sbc_err_sysprn(SBC_LOG_CMN_PRIO_ERR, 2,
                 SYS_LOG_HOST_BOOT,
                 SYS_LOG_APP_NAME,
                 SYS_LOG_CSC_NAME,
                 8,
                 SYS_LOG_EVT_DETECTION,
                 L"SSBL tampering check fail");

        p->bootst = SB_PROC_ST_ABNRAM;

        if(p->pvs_sw_bnk != 0) {
            _ucprint("** Previously FW exists.");
            sbc_err_sysprn(SBC_LOG_CMN_PRIO_ERR, 2,
                     SYS_LOG_HOST_BOOT,
                     SYS_LOG_APP_NAME,
                     SYS_LOG_CSC_NAME,
                     0,
                     SYS_LOG_EVT_DETECTION,
                     L"GCS Boot Mode Change from Update to Recovery");
            SBC_BootKeyModeChange(BOOT_MODE_RECOVERY, KEY_MODE_UPDATE, (VOID *)p);
            set_order = SBC_UC_MODE_RECOVERY;
            varsz = sizeof set_order;
            //_ucprint("UINTN size :%d", sizeof set_order);
            SBC_NvramSetVar((VOID *)sec_upt_name, (VOID *)&set_order, (VOID *)&varsz);
        }
        else {
            _ucprint("** Previously FW not exists.");
            sbc_err_sysprn(SBC_LOG_CMN_PRIO_ERR, 2,
                     SYS_LOG_HOST_BOOT,
                     SYS_LOG_APP_NAME,
                     SYS_LOG_CSC_NAME,
                     0,
                     SYS_LOG_EVT_DETECTION,
                     L"GCS Boot Mode Change from Update to Factory");

            SBC_BootKeyModeChange(BOOT_MODE_FACTORY, KEY_MODE_UPDATE, (VOID *)p);
            set_order = SBC_UC_MODE_FACTORY;
            varsz = sizeof set_order;
            //_ucprint("UINTN size :%d", sizeof set_order);
            SBC_NvramSetVar((VOID *)sec_upt_name, (VOID *)&set_order, (VOID *)&varsz);

        }

        sbc_err_sysprn(SBC_LOG_CMN_PRIO_ERR, 2,
                 SYS_LOG_HOST_BOOT,
                 SYS_LOG_APP_NAME,
                 SYS_LOG_CSC_NAME,
                 0,
                 SYS_LOG_EVT_DETECTION,
                 L"GCS Key Mode Change from Normal to Update");
        SBC_RawAlignedReadBlockIO(p->blkhnd, 0x0, 128, buf);
        _uc_mem_print_bin("Boot Mode Buf", buf, 128);


        
        SBC_GRUB_LoadAndStart(NULL);
        //SBC_ShutdownSystem();
        
        goto errdone;
    }

    sbc_err_sysprn(SBC_LOG_CMN_PRIO_ERR, 2,
         SYS_LOG_HOST_BOOT,
         SYS_LOG_APP_NAME,
         SYS_LOG_CSC_NAME,
         8,
         SYS_LOG_EVT_VALDIATION,
         L"SSBL tampering check Done");

errdone:


    return ret;
}


SBCStatus UC_RecoveryAbnormalAndNormal(VOID *handle)
{
    SBCStatus ret = SBCOK;
    boot_proc_t *p = (boot_proc_t *)handle;
    LV_t baseansr;
    UINT8 buf[1024] = {0, };
    

    _ucprint("*** Recovery Normal and Abnormal Use-case Test \n");
    ret = SBC_SSBL_Verify(p->blkhnd, &baseansr, p->curr_sw_bnk);
    if(ret != SBCOK) {
        sbc_err_sysprn(SBC_LOG_CMN_PRIO_ERR, 2,
                 SYS_LOG_HOST_BOOT,
                 SYS_LOG_APP_NAME,
                 SYS_LOG_CSC_NAME,
                 8,
                 SYS_LOG_EVT_DETECTION,
                 L"SSBL tampering check fail");

        p->bootst = SB_PROC_ST_ABNRAM;
        goto errdone;
    }

    sbc_err_sysprn(SBC_LOG_CMN_PRIO_ERR, 2,
         SYS_LOG_HOST_BOOT,
         SYS_LOG_APP_NAME,
         SYS_LOG_CSC_NAME,
         8,
         SYS_LOG_EVT_VALDIATION,
         L"On Recovery, SSBL tampering check Done");

    ret = SBC_GenMigrationKey((void *)p, ((atp_ident_t *)p->keyinfo)->migid);
    SBC_BuildHexFormattedMessage(
        (CONST VOID *)((atp_ident_t *)p->keyinfo)->migid,
        32,
        L"GCS_Mig_ID creation success (%s) \n",
        mrgmsg, sizeof mrgmsg);
    sbc_err_sysprn(SBC_LOG_CMN_PRIO_INFO, 2,
                 SYS_LOG_HOST_BOOT,
                 SYS_LOG_APP_NAME,
                 SYS_LOG_CSC_NAME,
                 1,
                 SYS_LOG_EVT_DETECTION,
                 mrgmsg);

    SBC_BuildHexFormattedMessage(
        (CONST VOID *)baseansr.value,
        16,
        L"Base Answer Encrypt (%s) \n",
        mrgmsg, sizeof mrgmsg);

    sbc_err_sysprn(SBC_LOG_CMN_PRIO_INFO, 2,
                 SYS_LOG_HOST_BOOT,
                 SYS_LOG_APP_NAME,
                 SYS_LOG_CSC_NAME,
                 1,
                 SYS_LOG_EVT_DETECTION,
                 mrgmsg);

    ret = SBC_RawAlignedWriteBlockIO(p->blkhnd,
                                     0x18000200, 
                                     16,
                                     baseansr.value);

    ret = SBC_RawAlignedReadBlockIO(p->blkhnd,
                                     0x18000200, 
                                     16,
                                     buf);

    SBC_BuildHexFormattedMessage(
        (CONST VOID *)buf,
        16,
        L"Base Read Message (%s) \n",
        mrgmsg, sizeof mrgmsg);

    sbc_err_sysprn(SBC_LOG_CMN_PRIO_INFO, 2,
                 SYS_LOG_HOST_BOOT,
                 SYS_LOG_APP_NAME,
                 SYS_LOG_CSC_NAME,
                 1,
                 SYS_LOG_EVT_DETECTION,
                 mrgmsg);
errdone:

    switch(p->bootst) {
    case SB_PROC_ST_ABNRAM:
        sbc_err_sysprn(SBC_LOG_CMN_PRIO_ERR, 2,
                 SYS_LOG_HOST_BOOT,
                 SYS_LOG_APP_NAME,
                 SYS_LOG_CSC_NAME,
                 0,
                 SYS_LOG_EVT_DETECTION,
                 L"GCS Boot Mode Change from Recovery to Factory");
        SBC_BootKeyModeChange(BOOT_MODE_FACTORY, KEY_MODE_UPDATE, (VOID *)p);
        SBC_RawAlignedReadBlockIO(p->blkhnd, 0x0, 128, buf);
        _uc_mem_print_bin("Boot Mode Buf", buf, 128);
        SBC_GRUB_LoadAndStart(NULL);
        break;
    case SB_PROC_ST_NRMA:
        sbc_err_sysprn(SBC_LOG_CMN_PRIO_ERR, 2,
                 SYS_LOG_HOST_BOOT,
                 SYS_LOG_APP_NAME,
                 SYS_LOG_CSC_NAME,
                 0,
                 SYS_LOG_EVT_DETECTION,
                 L"GCS Boot Mode Change from Recovery to NOrmal");
        SBC_BootKeyModeChange(BOOT_MODE_NORMAL, KEY_MODE_NORMAL, (VOID *)p);
        SBC_RawAlignedReadBlockIO(p->blkhnd, 0x0, 128, buf);
        _uc_mem_print_bin("Boot Mode Buf", buf, 128);
        SBC_GRUB_LoadAndStart(NULL);
        break;
    default:
        break;
    }


    return ret;
}

