[Defines]
  PLATFORM_NAME                = SBC 
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
   RngLib|MdeModulePkg/Library/BaseRngLibTimerLib/BaseRngLibTimerLib.inf
   BaseCryptLib|CryptoPkg/Library/BaseCryptLib/BaseCryptLib.inf
   OpensslLib|CryptoPkg/Library/OpensslLib/OpensslLibFull.inf
#
   ResetSystemLib|MdeModulePkg/Library/RuntimeResetSystemLib/RuntimeResetSystemLib.inf
!ifdef $(DEBUG_ON_SERIAL_PORT)
   DebugLib|MdePkg/Library/BaseDebugLibSerialPort/BaseDebugLibSerialPort.inf
!else
   DebugLib|OvmfPkg/Library/PlatformDebugLibIoPort/PlatformDebugLibIoPort.inf
!endif
   TimerLib|MdePkg/Library/SecPeiDxeTimerLibCpu/SecPeiDxeTimerLibCpu.inf


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

   UefiBootManagerLib|MdeModulePkg/Library/UefiBootManagerLib/UefiBootManagerLib.inf
   HobLib|MdePkg/Library/DxeHobLib/DxeHobLib.inf
   PerformanceLib|MdePkg/Library/BasePerformanceLibNull/BasePerformanceLibNull.inf
   DxeServicesTableLib|MdePkg/Library/DxeServicesTableLib/DxeServicesTableLib.inf
   DxeServicesLib|MdePkg/Library/DxeServicesLib/DxeServicesLib.inf
   ReportStatusCodeLib|MdePkg/Library/BaseReportStatusCodeLibNull/BaseReportStatusCodeLibNull.inf

   PeCoffGetEntryPointLib|MdePkg/Library/BasePeCoffGetEntryPointLib/BasePeCoffGetEntryPointLib.inf
   BcfgCommandLib|ShellPkg/Library/UefiShellBcfgCommandLib/UefiShellBcfgCommandLib.inf
   AcpiViewCommandLib|ShellPkg/Library/UefiShellAcpiViewCommandLib/UefiShellAcpiViewCommandLib.inf
   IoLib|MdePkg/Library/BaseIoLibIntrinsic/BaseIoLibIntrinsic.inf

   ShellLib|ShellPkg/Library/UefiShellLib/UefiShellLib.inf
   ShellCommandLib|ShellPkg/Library/UefiShellCommandLib/UefiShellCommandLib.inf
   HandleParsingLib|ShellPkg/Library/UefiHandleParsingLib/UefiHandleParsingLib.inf

[PcdsFixedAtBuild]
  gEfiMdePkgTokenSpaceGuid.PcdDebugPropertyMask|0x1F
  gEfiMdePkgTokenSpaceGuid.PcdDebugPrintErrorLevel|0x80000045
  gEfiMdePkgTokenSpaceGuid.PcdUefiLibMaxPrintBufferSize|16000
  #  0-PCANSI, 1-VT100, 2-VT00+, 3-UTF8, 4-TTYTERM
  gEfiMdePkgTokenSpaceGuid.PcdDefaultTerminalType|1
  # For COM2 (standard I/O base address)
  #gEfiMdeModulePkgTokenSpaceGuid.PcdSerialRegisterBase|0x2F8
  #gEfiMdeModulePkgTokenSpaceGuid.PcdSerialBaudRate|115200         # Or your desired baud rate
  #gEfiMdeModulePkgTokenSpaceGuid.PcdSerialClockRate|1843200        # Common for 16550 UARTs


#Added by Leon

  # Base address of the UART controller (e.g., COM1)
  #gEfiMdeModulePkgTokenSpaceGuid.PcdSerialPortBaseAddress|0x3F8



  # Baud rate for the serial port
  #gEfiMdeModulePkgTokenSpaceGuid.PcdSerialPortBaudRate|115200

  # Number of data bits (typically 8)
  #gEfiMdeModulePkgTokenSpaceGuid.PcdSerialPortDataBits|8

  # Parity (N=None, O=Odd, E=Even)
  #gEfiMdeModulePkgTokenSpaceGuid.PcdSerialPortParity|1

  # Number of stop bits (typically 1)
  #gEfiMdeModulePkgTokenSpaceGuid.PcdSerialPortStopBits|1

  # Stride between UART registers (1 for byte-addressed, 4 for DWORD-addressed, etc.)
  #gEfiMdeModulePkgTokenSpaceGuid.PcdSerialPortRegisterStride|1

  # Clock rate of the UART controller in Hz (e.g., 1.8432 MHz for 16550)
  #gEfiMdeModulePkgTokenSpaceGuid.PcdSerialClockRate|1843200

  # Enable/Disable hardware flow control (RTS/CTS)
  #gEfiMdeModulePkgTokenSpaceGuid.PcdSerialUseHardwareFlowControl|FALSE

  # Debug Print Error Level: controls what DEBUG() messages are printed.
  # For verbose output during boot, use a higher value.
  # 0x8000004F includes DEBUG_ERROR | DEBUG_WARN | DEBUG_INFO | DEBUG_LOAD
  # 0xFFFFFFFF for DEBUG_ALL (very verbose)
  #gEfiMdeModulePkgTokenSpaceGuid.PcdDebugPrintErrorLevel|0x80000045

  #gEfiMdeModulePkgTokenSpaceGuid.PcdDefaultConInDevicePath|L"VenHw(D3987D4B-971A-435F-8CAF-4967EB627241)/Uart(115200,8,N,1)/"
  #gEfiMdeModulePkgTokenSpaceGuid.PcdDefaultConOutDevicePath|L"VenHw(D3987D4B-971A-435F-8CAF-4967EB627241)/Uart(115200,8,N,1)/"
  #gEfiMdeModulePkgTokenSpaceGuid.PcdDefaultErrOutDevicePath|L"VenHw(D3987D4B-971A-435F-8CAF-4967EB627241)/Uart(115200,8,N,1)/"
#Added Close

[Components]
   SBCPkg/Application/FSBL/FSBL.inf
   SBCPkg/Application/SSBL/SSBL.inf

   ShellPkg/Library/UefiShellLib/UefiShellLib.inf
   FtdiUsbSerialDxe/FtdiUsbSerialDxe.inf

   MdeModulePkg/Universal/Console/TerminalDxe/TerminalDxe.inf
   MdeModulePkg/Universal/SerialDxe/SerialDxe.inf {
	<LibraryClasses>
		DebugLib|MdePkg/Library/BaseDebugLibSerialPort/BaseDebugLibSerialPort.inf
		#DebugLib|MdePkg/Library/BaseDebugLibNull/BaseDebugLibNull.inf
		SerialPortLib|MdeModulePkg/Library/BaseSerialPortLib16550/BaseSerialPortLib16550.inf
		PlatformHookLib|MdeModulePkg/Library/PlatformHookLibSerialPortPpi/PlatformHookLibSerialPortPpi.inf
		PciLib|MdePkg/Library/BasePciLibCf8/BasePciLibCf8.inf	
		IoLib|MdePkg/Library/BaseIoLibIntrinsic/BaseIoLibIntrinsic.inf
		PciCf8Lib|MdePkg/Library/BasePciCf8Lib/BasePciCf8Lib.inf
   }

[BuildOptions]
