[Defines]
  PLATFORM_NAME                = FSBL
  PLATFORM_GUID                = 8c0d1e3a-4e8b-4b2a-8c5e-8f2e3a4e8b2a
  PLATFORM_VERSION             = 1.0
  BUILD_TARGETS                = DEBUG|RELEASE
  SKUID_IDENTIFIER             = DEFAULT
  DSC_SPECIFICATION            = 0x00010005
  SUPPORTED_ARCHITECTURES      = IA32|X64
  OUTPUT_DIRECTORY             = Build/SBC


!include MdePkg/MdeLibs.dsc.inc
#!include MdePkg/MdePkg.dsc.inc
#!include MdeModulePkg/MdeModulePkg.dsc.inc

[LibraryClasses]
	IntrinsicLib|CryptoPkg/Library/IntrinsicLib/IntrinsicLib.inf
#  RngLib|MdeModulePkg/Library/BaseRngLibTimerLib/BaseRngLibTimerLib.inf
#  BaseCryptLib|CryptoPkg/Library/BaseCryptLib/BaseCryptLib.inf
#  OpensslLib|CryptoPkg/Library/OpensslLib/OpensslLibFull.inf
#
    ResetSystemLib|MdeModulePkg/Library/RuntimeResetSystemLib/RuntimeResetSystemLib.inf
!ifdef $(DEBUG_ON_SERIAL_PORT)
  DebugLib|MdePkg/Library/BaseDebugLibSerialPort/BaseDebugLibSerialPort.inf
!else
  DebugLib|OvmfPkg/Library/PlatformDebugLibIoPort/PlatformDebugLibIoPort.inf
!endif
#  TimerLib|MdePkg/Library/SecPeiDxeTimerLibCpu/SecPeiDxeTimerLibCpu.inf


[LibraryClasses.common]
  UefiApplicationEntryPoint|MdePkg/Library/UefiApplicationEntryPoint/UefiApplicationEntryPoint.inf
  UefiDriverEntryPoint|MdePkg/Library/UefiDriverEntryPoint/UefiDriverEntryPoint.inf
  UefiBootServicesTableLib|MdePkg/Library/UefiBootServicesTableLib/UefiBootServicesTableLib.inf
  DevicePathLib|MdePkg/Library/UefiDevicePathLib/UefiDevicePathLibOptionalDevicePathProtocol.inf
!if $(TARGET) == RELEASE
  DebugLib|MdePkg/Library/BaseDebugLibNull/BaseDebugLibNull.inf
!else
  DebugLib|MdePkg/Library/UefiDebugLibConOut/UefiDebugLibConOut.inf
!endif
  DebugPrintErrorLevelLib|MdePkg/Library/BaseDebugPrintErrorLevelLib/BaseDebugPrintErrorLevelLib.inf
  PcdLib|MdePkg/Library/BasePcdLibNull/BasePcdLibNull.inf
  MemoryAllocationLib|MdePkg/Library/UefiMemoryAllocationLib/UefiMemoryAllocationLib.inf
  UefiLib|MdePkg/Library/UefiLib/UefiLib.inf
  BaseLib|MdePkg/Library/BaseLib/BaseLib.inf
  BaseMemoryLib|MdePkg/Library/BaseMemoryLib/BaseMemoryLib.inf
  PrintLib|MdePkg/Library/BasePrintLib/BasePrintLib.inf
  FileHandleLib|MdePkg/Library/UefiFileHandleLib/UefiFileHandleLib.inf
  SortLib|MdeModulePkg/Library/UefiSortLib/UefiSortLib.inf
  UefiRuntimeServicesTableLib|MdePkg/Library/UefiRuntimeServicesTableLib/UefiRuntimeServicesTableLib.inf
  UefiHiiServicesLib|MdeModulePkg/Library/UefiHiiServicesLib/UefiHiiServicesLib.inf
  HiiLib|MdeModulePkg/Library/UefiHiiLib/UefiHiiLib.inf
  VariablePolicyHelperLib|MdeModulePkg/Library/VariablePolicyHelperLib/VariablePolicyHelperLib.inf

  


[Components]
  FSBL_PKG/Application/FSBL/FSBL.inf
