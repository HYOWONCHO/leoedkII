import subprocess


def get_baseboard_sn():
    serial_number = subprocess.check_output("sudo dmidecode -s baseboard-serial-number", shell=True).decode().strip()
    return serial_number


def get_ssd_serial():
    result = subprocess.run(['lsblk', '-dn', '-o', 'NAME'], capture_output=True, text=True, check=True)
    devices = result.stdout.strip().split('\n')
    serials = {}

    for device in devices:
        device_path = f'/dev/{device}'
        udevadm_result = subprocess.run(['udevadm', 'info', '--query=all', '--name', device_path], capture_output=True, text=True, check=True)
        info = udevadm_result.stdout

        for line in info.split('\n'):
            if 'ID_SERIAL=' in line:
                serial = line.split('=')[1].strip()
                serials[device] = serial
                return serial 

    return serials

def get_memory_serial():
    serial_number = subprocess.check_output("sudo dmidecode --type 1 | grep 'Serial Number'", shell=True).decode().strip()
    return serial_number


