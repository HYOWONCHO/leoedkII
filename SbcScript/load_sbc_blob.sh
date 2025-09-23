#!/usr/bin/env bash

# Define colors
RED='\e[31m'
GREEN='\e[32m'
YELLOW='\e[33m'
BLUE='\e[34m'
MAGENTA='\e[35m'
CYAN='\e[36m'
WHITE='\e[37m'
NC='\e[0m' # No Color



OPTS=$(getopt -o hv -l help,verbose,\
                            output:,\
                            upload-bnk1:,\
                            upload-bnk2: \
                            -- "$@")

if [ $? != 0 ]; then
    echo "Failed to option parsing" 
    exit 1;
fi

#echo $OPTS
eval set -- "$OPTS"


help_usage()
{
    echo "$@ Help Usage"
}

add_firmware_length()
{
    size=$(stat -c%s $1)
    printf "$(printf '\\x%02x\\x%02x\\x%02x\\x%02x' $((size & 0xFF)) $(((size >> 8) & 0xFF)) $(((size >> 16) & 0xFF)) $(((size >> 24) & 0xFF)))" | cat - $1 > $2
}

fw_upload_to_bank1()
{
    pushd bank1
    if [ $? -ne 0 ]; then
        echo -e "${YELLOW}Can not find the bank1 directory...${NC}"
        return 0
    fi

    add_firmware_length fsbl.efi fsbl.efi.bin
    add_firmware_length ssbl.efi ssbl.efi.bin

    echo -e "${GREEN} FSBL upload in Bank 1 ${NC}"
    dd if=./fsbl.efi.bin of=/dev/nvme0n1p4 seek=$(printf "%d" 0x200) bs=1 count=$(stat -c%s "fsbl.efi.bin")


    echo -e "${GREEN} SSBL upload in Bank 1 ${NC}"
    dd if=./ssbl.efi.bin of=/dev/nvme0n1p4 seek=$(printf "%d" 0x400200) bs=1 count=$(stat -c%s "ssbl.efi.bin")
    popd

}

fw_upload_to_bank2()
{
    pushd bank2
    if [ $? -ne 0 ]; then
        echo -e "${YELLOW}Can not find the bank1 directory...${NC}"
        return 0
    fi

    add_firmware_length fsbl.efi fsbl.efi.bin
    add_firmware_length ssbl.efi ssbl.efi.bin

    echo -e "${GREEN} FSBL upload in Bank 2 ${NC}"
    dd if=./fsbl.efi.bin of=/dev/nvme0n1p4 seek=$(printf "%d" 0x8000200) bs=1 count=$(stat -c%s "fsbl.efi.bin")


    echo -e "${GREEN} SSBL upload in Bank 2 ${NC}"
    dd if=./ssbl.efi.bin of=/dev/nvme0n1p4 seek=$(printf "%d" 0x8400200) bs=1 count=$(stat -c%s "ssbl.efi.bin")
    popd

}

check_and_create_bankdir()
{
    if [ ! -d "./bank1" ]; then
        mkdir -p "./bank1"
    fi

    if [ ! -d "./bank2" ]; then
        mkdir -p "./bank2"
    fi
}


check_and_create_bankdir

#while [[ $# -gt 0 ]]; do
#while [[ $# -gt 0 ]]; do
while true; do
    case "$1" in
        -h|--help)
            help_usage 
            shift
            ;;
        -v|--verbose)
            echo "Verbose ..."
            shift
            ;;
        --output)
            OUTPUT="$2"
            echo "Output... $OUTPUT"
            shift 2
            ;;
        --upload-bnk1)
            fw_upload_to_bank1 
            shift 
            ;;
        --upload-bnk2)
            fw_upload_to_bank2
            shift 
            ;;
        --)
            shift
            break
            ;;
    esac
done

echo "reminded argument : $@"




