import platform
import re
import socket
import uuid

import psutil

if __name__ == '__main__':

    print(f'Machine: {platform.machine()}')
    print(f'Version: {platform.version()}')
    print(f'Uname: {platform.uname()}')
    print(f'Platform: {platform.platform()}')
    print(f'Release: {platform.release()}')
    print(f'System: {platform.system()}')
    print(f'Processor: {platform.processor()}')

    hostname: str = socket.gethostname()
    ipaddress: str = socket.gethostbyname(hostname)
    mac: str = ':'.join(re.findall('..', '%012x' % uuid.getnode()))

    print(f'\nHostname: {hostname}')
    print(f'IP Address: {ipaddress}')
    print(f'MAC Address: {mac}')

    ram = str(round(psutil.virtual_memory().total / (1024.0 ** 3))) + " GB"
    print(f'RAM Total: {ram}')

    pass
