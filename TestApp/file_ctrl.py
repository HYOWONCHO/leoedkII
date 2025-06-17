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

    return content
