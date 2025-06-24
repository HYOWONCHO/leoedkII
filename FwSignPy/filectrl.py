import os
from pathlib import Path


def get_image_size(fname):
    fpath = Path(fname)
    return fpath.stat().st_size

def read_image(fname):
    try:
        with open(fname, "rb") as file:
            content = file.read()
            file.close()
    except FileNotFoundError:
        print(f"\n Read file '{fname}' not found")

    return content

def write_image_xcnt(fname , wrdata, fmode, xcnt):
    try:
        with open(fname, fmode) as file:
            for item  in range(xcnt):
                file.write(wrdata[item].to_bytes(1, byteorder='little', signed=False))
            file.close()
    except FileNotFoundError:
        print(f"\n Write file '{fname}' not found")

def write_image(fname , wrdata, fmode):
    try:
        with open(fname, fmode) as file:
            file.write(wrdata)
            file.close()
    except FileNotFoundError:
        print(f"\n Write file '{fname}' not found")

