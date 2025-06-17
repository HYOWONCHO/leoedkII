import sys
import hashlib
import os

import hw_info
import file_ctrl

def hw_unique_info_print(baseboard, memory, ssd):
    print("base board sn : " + baseboard);
    print("memory sn : " + memory);
    print("ssd sn : " + ssd);

def compute_device_id(buffers):
    sha256 = hashlib.sha256()
    for buffer in buffers:
        sha256.update(buffer)
    return sha256.hexdigest()

def read_fsblimg():
    fname = "./FSBL.efi"
    if file_ctrl.file_is_exists(fname) != True:
        print("File doee not exists")
        sys.exit()
    else:
        print("File Exists")

    flen = file_ctrl.get_file_length(fname)
    rdimg = file_ctrl.read_file(fname)

    return rdimg

def read_ssblimg():
    fname = "./SSBL.efi"
    if file_ctrl.file_is_exists(fname) != True:
        print("File doee not exists")
        sys.exit()
    else:
        print("File Exists")

    flen = file_ctrl.get_file_length(fname)
    rdimg = file_ctrl.read_file(fname)

    return rdimg


if __name__ == "__main__":

    fname = "./test_raw.bin"

    baseboard_sn = hw_info.get_baseboard_sn()
    memory_sn = hw_info.get_memory_serial()
    ssd_sn = hw_info.get_ssd_serial()

    hw_unique_info_print(baseboard_sn, memory_sn, ssd_sn)


    rdimg = read_fsblimg()
    devidlist = [baseboard_sn.encode(), memory_sn.encode(), ssd_sn.encode(), rdimg.encode()]
    devid = compute_device_id(devidlist)
    print(devid)

    os.remove(fname);
    
    file_ctrl.write_header_info(fname)




