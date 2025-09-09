#!/bin/sh

cp -af ../Build/SBC/DEBUG_GCC5/X64/SSBL.efi  SSBL.efi
if [ $? != 0 ]; then
    printf "SSBL copy is not done \n"
    exit
fi

printf "SSBL copy is OK ... \n"

python fw_sign.py SSBL.efi
if [ $? != 0 ]; then
    printf "SSBL Firmware sign not done \n"
    exit
fi

printf "SSBL Sign is OK ... \n"


