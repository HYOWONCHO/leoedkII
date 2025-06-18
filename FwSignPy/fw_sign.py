import os
import array


import filectrl
import fwcrypt


base_answer = "rlwlekqdksrlfdl."
fw_info = "bjadnpdjwjdqhrlf"

fwfname     = "FFSBL.efi"
rootcaf     = "root_ca_ecc.crt.der"
rootkeyf    = "root_ca_ecc.key"

def compute_dsa(certibytes, content):

    hasher  = Hash(Sha256) 

    return signval



if __name__ == "__main__":

    
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


 

    digest  = fwcrypt.sha256_compute(content)
    print(f"Digest {digest.hex()}")

  
    signature = fwcrypt.compute_ec_dsa(privkey, digest)
    print(f"Signature len : {len(signature)}")
    print(f"Signature return : {signature.hex()}")



    
    content = content + baseanswers + fwinfos + certibytes 

    filectrl.write_image(fwfname + ".bin", content, "wb")
    filectrl.write_image(fwfname + ".bin", signature , "ab")


    # "i" means signed integer, typically 2 or 4 bytes
    binfo = array.array('b',[len(signature),len(fw_info)])
    filectrl.write_image(fwfname + ".bin", binfo , "ab")
    binfo = array.array('h',[certilen]) 
    filectrl.write_image(fwfname + ".bin", binfo , "ab")

    binfo = array.array('b', [len(base_answer), 1,  35,  36])
    filectrl.write_image(fwfname + ".bin", binfo , "ab")








