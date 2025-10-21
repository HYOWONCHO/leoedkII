#!/usr/bin/env bash


set -e

adding_length_in_image()
{
    local _size=$(stat -c%s $1)

    printf "$(printf '\\x%02x\\x%02x\\x%02x\\x%02x' $((size & 0xFF)) $(((size >> 8) & 0xFF)) $(((size >> 16) & 0xFF)) $(((size >> 24) & 0xFF)))" | cat - $1 > $2


}

fsbl_img_copy_on_bank()
{
    local bnkid=$1
    local if_name=$2
    local of_name=$3
    local cpyaddr=$4

    #
    # If file does not exist, return 
    #
    
    [ -f $if_name ] || {echo "$if_name file not found"; return 1}
    [ -f $of_name ] || {echo "$of_name file not found"; return 1}

    local _seek=$(printf "%d" $cpyaddr)
    local _count=$(stat -c%s $if_name)

    echo "Write the FSBL Image in Bank $bnkid, Addr $_seek"

    $(which dd) if=$if_name of=$of_name seek=$_seek bs=1 count=$_count

}

ssbl_img_copy_on_bank()
{
    local bnkid=$1
    local if_name=$2
    local of_name=$3
    local cpyaddr=$4

    #
    # If file does not exist, return 
    #
    
    [ -f $if_name ] || {echo "$if_name file not found"; return 1}
    [ -f $of_name ] || {echo "$of_name file not found"; return 1}

    local _seek=$(printf "%d" $cpyaddr)
    local _count=$(stat -c%s $if_name)

    echo "Write the SSBL Image in Bank $bnkid, Addr $_seek"

    $(which dd) if=$if_name of=$of_name seek=$_seek bs=1 count=$_count

}





fsbl_img_copy_on_bank 1  fsbl.efi.bin  /dev/nvme0n1p4 0x200
