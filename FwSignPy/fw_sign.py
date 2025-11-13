#!/usr/bin/env python3

import os
import array
import sys


import filectrl
import fwcrypt


base_answer = "sat-based-answer"
fw_info = "fw_v_1.0"

#fwfname     = "FSBL.efi"
rootcaf     = "SBC.der"
rootkeyf    = "SBC.key"

def compute_dsa(certibytes, content):

    hasher  = Hash(Sha256) 

    return signval

def make_rawfs_bin():
    flen = filectrl.get_image_size(fwfname + ".bin")

    print(f"The '{fwfname}'.bin file size {flen}")
    print(f"The '{fwfname}'.bin file size  {hex(flen)}")
    content = filectrl.read_image(fwfname + ".bin")

    binfo = array.array('I',[flen])
    filectrl.write_image(fwfname + ".rawfs", binfo, "wb");
    filectrl.write_image(fwfname + ".rawfs", content, "ab")


def make_fsbl_image():
    baseanswers = base_answer.encode()
    fwinfos = fw_info.encode()
    flen = filectrl.get_image_size(fwfname)
    print(f"The '{fwfname}' file size {flen}")
    certilen = filectrl.get_image_size(rootcaf)
    pkeylen = filectrl.get_image_size(rootkeyf)




    content = filectrl.read_image(fwfname)
    
     
    certibytes = filectrl.read_image(rootcaf)


    privkey = fwcrypt.load_ec_private_key_from_pem(rootkeyf)


    pubkey = privkey.public_key()

    print("Private key (raw object) :", privkey)
    print("Public key (raw object) :", pubkey)

    #certipem = fwcrypt.read_pem_file("root_ca_ecc.crt")
    #print("Roott CA")
    #print(certipem)



    #fwcrypt.compute_ec_dsa_verify(pubkey, signature,digest)


    content = content + baseanswers + fwinfos + certibytes

    digest  = fwcrypt.sha256_compute(content)
    print(f"Digest {digest.hex()}")


    signature = fwcrypt.compute_ec_dsa_sign(privkey, digest)
    print(f"Signature len : {len(signature)}")
    print(f"Signature return : {signature}")



    
    filectrl.write_image(fwfname + ".bin", content, "wb")
    filectrl.write_image(fwfname + ".bin", signature , "ab")

    # "i" means signed integer, typically 2 or 4 bytes
    binfo = array.array('b',[len(signature),len(fw_info)])
    filectrl.write_image(fwfname + ".bin", binfo , "ab")
    binfo = array.array('h',[certilen])
    filectrl.write_image(fwfname + ".bin", binfo , "ab")

    binfo = array.array('b', [len(base_answer), 1,  35,  36])
    filectrl.write_image(fwfname + ".bin", binfo , "ab")


if __name__ == "__main__":

    if len(sys.argv) < 2:
        print(f"Usage : fw_sign.py firmware_file_name")
        sys.exit(1)

    
    fwfname = sys.argv[1]
    #fwfname_rawfs = sys.argv[1] + "_rawfs"
    print(f"Sign Firmware Name : ${fwfname}")
    make_fsbl_image()

    make_rawfs_bin();





    #fwcrypt.ecdsa_sign_verify_test()



