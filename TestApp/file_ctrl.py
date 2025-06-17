import os
from pathlib import Path


def get_file_length(fname):
    file_path = Path(fname)
    return file_path.stat().st_size


def file_is_exists(fname):
    file_path = Path(fname)
    if file_path.exists():
        return True
    else:
        return False

def read_file(fname):
    with open(fname, "r") as file:
        content = file.read()
        file.close()

    return content

def write_file(fname, fdata, mode):
    binary_f = open(fname, mode)
    binary_f.write(fdata)
    binary_f.close()


def write_header_info(fname):
    # Write the magic ID 
    if file_is_exists(fname) != True:
        print("write binary file create ")
        write_file(fname, "AA55AA55", "wb")
    else:
        print("append binary file create ")
        write_file(fname, "AA55AA55", "ab")
