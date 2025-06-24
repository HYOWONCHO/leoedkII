import numpy as np
import binascii
import array
import filectrl


imgname = "rawprt.bin"

rootca_path = "root_ca_ecc.crt.der"
devidcrt_path = "root_ca_ecc.crt.der"
fwidcrt_path = "root_ca_ecc.crt.der"
osidcrt_path = "root_ca_ecc.crt.der"

fsbl_path = "FSBL.efi"
ssbl_path = "SSBL.efi"

#onek = 1024 << 2
fsbl_sector = 4 << 20 #4M
ssbl_sector = 4 << 20
os_sector = 20 << 20
bootsw_sector = 100 << 20

boot_sector = 128 << 20 #128M

def need_to_zero_padding(desired_len, myarray):

    #print(f"desired len : {desired_len}, myarray size   : {len(myarray)} ") 
    #padding_need = desired_len - len(myarray)

    #if padding_need > 0:
    zero_padding = b'\x00' * desired_len
    myarray.extend(zero_padding)

def make_fw_image():
    copy_cnt = 0 
    fwimg_array = bytearray(boot_sector)
    #print(f"contounst fwimgcontents len is {hex(len(fwimg_array))}")

    fsbl_len = filectrl.get_image_size(fsbl_path)
    fsbl_content =  filectrl.read_image(fsbl_path)

    ssbl_len = filectrl.get_image_size(ssbl_path)
    ssbl_content =  filectrl.read_image(ssbl_path)


    os_len = filectrl.get_image_size(fsbl_path)
    os_content = filectrl.read_image(fsbl_path)

    sw_len = filectrl.get_image_size(ssbl_path)
    sw_content = filectrl.read_image(ssbl_path)

    print(f"fsbl address : {fsbl_len.to_bytes(4, byteorder='little', signed=False)}")
    fwimg_array[copy_cnt : 4] = fsbl_len.to_bytes(4, byteorder='little', signed=False)
    copy_cnt += 4
    

    fwimg_array[copy_cnt : fsbl_len] = fsbl_content
    copy_cnt += fsbl_sector - 4

    #print(f"ssbl address : {hex(copy_cnt + 512)}")
    fwimg_array[copy_cnt : 4] = ssbl_len.to_bytes(4, byteorder='little', signed=False)
    copy_cnt += 4

    fwimg_array[copy_cnt : ssbl_len] = fsbl_content
    copy_cnt += fsbl_sector - 4 


    #print(f"os address : {hex(copy_cnt + 512)}")
    fwimg_array[copy_cnt : 4] = os_len.to_bytes(4, byteorder='little', signed=False)
    copy_cnt += 4

    fwimg_array[copy_cnt : os_len] = os_content
    copy_cnt += os_sector - 4

    #print(f"sw address : {hex(copy_cnt + 512)}")
    fwimg_array[copy_cnt : 4] = sw_len.to_bytes(4, byteorder='little', signed=False)
    copy_cnt += 4

    fwimg_array[copy_cnt : sw_len] = sw_content
    copy_cnt += bootsw_sector - 4

    #print(fwimg_array.hex())
    #copy_cnt +=  fsbl_sector
    #fwimg_array[csopy_cnt :ssbl_sector ] = ssbl_content

    #print(f"Sector size {hex(copy_cnt)}")

    fwimg_array = fwimg_array[:boot_sector]
    return fwimg_array


    


def make_rawprt_header():
    magic_id = "AA55AA55"
    prtinfo = b"LIGFS+V1.0"
    bootpres = "0001004300020050"
    rawprt_header = bytearray(0)

    rawprt_header.extend(bytes.fromhex(magic_id));
    rawprt_header.extend(prtinfo)
    need_to_zero_padding(64 - len(prtinfo), rawprt_header)
    need_to_zero_padding(52, rawprt_header)
    rawprt_header.extend(bytes.fromhex(bootpres))
    need_to_zero_padding(384, rawprt_header)
    
    
    #rawprt_header.extend(ord('!') * 128)

#   rawprt_header[0:len(magic_id)] = bytes.fromhex(magic_id)
#   rawprt_header[4:len(prtinfo)] = prtinfo.encode('utf-8')
#   rawprt_header[120:8] =  bytes.fromhex(bootpres)
#   return_bytes = binascii.hexlify(rawprt_header)
#   return_string = return_bytes.decode('ascii')
#   print(return_string)
    #print(array.array('i', bootpres))

   
    return rawprt_header


def make_bootfw_storage():

    
    bootfw_stg = bytearray()

    #
    # Base Answer and RES empty ( that is, it is fill-up the zero )
    #
    need_to_zero_padding(128, bootfw_stg)
    
    rootcalen = filectrl.get_image_size(rootca_path);
    rootca_ds = filectrl.read_image(rootca_path);
    bootfw_stg.extend(rootcalen.to_bytes(4, byteorder='little', signed=False))
    bootfw_stg.extend(rootca_ds);
    need_to_zero_padding(2048 - rootcalen, bootfw_stg)

    devidcrt_len = filectrl.get_image_size(devidcrt_path);
    devidcrt_ds = filectrl.read_image(devidcrt_path);
    bootfw_stg.extend(devidcrt_len.to_bytes(4, byteorder='little', signed=False))
    bootfw_stg.extend(devidcrt_ds);
    need_to_zero_padding(2048 - devidcrt_len, bootfw_stg)

    fwidcrt_len = filectrl.get_image_size(fwidcrt_path);
    fwidcrt_ds = filectrl.read_image(fwidcrt_path);
    bootfw_stg.extend(fwidcrt_len.to_bytes(4, byteorder='little', signed=False))
    bootfw_stg.extend(fwidcrt_ds);
    need_to_zero_padding(2048 - fwidcrt_len, bootfw_stg)

    osidcrt_len = filectrl.get_image_size(osidcrt_path);
    osidcrt_ds = filectrl.read_image(osidcrt_path);
    bootfw_stg.extend(osidcrt_len.to_bytes(4, byteorder='little', signed=False))
    bootfw_stg.extend(osidcrt_ds);
    need_to_zero_padding(2048 - osidcrt_len, bootfw_stg)

    #
    # SW_LIST_OFFSET( that is, it is fill-up the zero )
    # 8k 
    #
    need_to_zero_padding(8 << 10, bootfw_stg)

    return bootfw_stg




if __name__ == "__main__":

    next_address = 0

    print(f"Make RAW Partition Header ... (Address {hex(next_address)}) ")
    prtheader = make_rawprt_header()
    

    filectrl.write_image(imgname, prtheader, "wb")


    next_address += len(prtheader)
    print(f"Make Boot FW Bank 1 Header ... (Address {hex(next_address)})  ")
    fwimgcontents = make_fw_image()
    #print(f"fwimgcontents len is {hex(len(fwimgcontents))}")
    filectrl.write_image(imgname, fwimgcontents, "ab")

    next_address += len(fwimgcontents)
    print(f"Make Boot FW Bank 2 Header ... (Address {hex(next_address)})  ")
    fwimgcontents = make_fw_image()
    #print(f"fwimgcontents len is {hex(len(fwimgcontents))}")
    filectrl.write_image(imgname, fwimgcontents, "ab")

    next_address += len(fwimgcontents)
    print(f"Make Boot FW Bank Factory Header ... (Address {hex(next_address)})  ")
    fwimgcontents = make_fw_image()
    #print(f"fwimgcontents len is {hex(len(fwimgcontents))}")
    filectrl.write_image(imgname, fwimgcontents, "ab")

    next_address += len(fwimgcontents)
    print(f"Make Boot FW Bank Last Header ... (Address {hex(next_address)})  ")

    sys_stg_content = make_bootfw_storage()
    filectrl.write_image(imgname, sys_stg_content, "ab")
    next_address += len(sys_stg_content)
    print(f"System Setting Storage Last Header ... (Address {hex(next_address)})  ")

