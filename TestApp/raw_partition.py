import sys
import hashlib

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




if __name__ == "__main__":
    baseboard_sn = hw_info.get_baseboard_sn()
    memory_sn = hw_info.get_memory_serial()
    ssd_sn = hw_info.get_ssd_serial()

    hw_unique_info_print(baseboard_sn, memory_sn, ssd_sn)

    fname = "./FSBL.efi"
    if file_ctrl.file_is_exists(fname) != True:
        print("File doee not exists")
        sys.exit()
    else:
        print("File Exists")

    flen = file_ctrl.get_file_length(fname)
    rdimg = file_ctrl.read_file(fname)

    devid = compute_device_id([baseboard_sn, memory_sn, ssd_sn, rdimg])
    print(devid)
    



