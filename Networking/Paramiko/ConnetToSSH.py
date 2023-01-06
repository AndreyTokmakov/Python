import sys

import paramiko
from scp import SCPClient


def connect_test():
    host, login, password = '192.168.1.5', 'root', 'root'

    # cmd: str = "ps axf"
    cmd: str = "ls -l"

    client = paramiko.SSHClient()
    client.set_missing_host_key_policy(paramiko.AutoAddPolicy())
    client.connect(hostname=host,
                   username=login,
                   password=password,
                   port=22,
                   look_for_keys=False,
                   allow_agent=False)
    stdin, stdout, stderr = client.exec_command(cmd)
    data = stdout.read() + stderr.read()
    client.close()

    print(data)


def progress(filename,
             file_size: float,
             file_sent: float):
    sys.stdout.write(f"{filename} progress: {file_sent/file_size*100}%\r")


def upload_file():
    host, login, password = '192.168.1.5', 'root', 'root'
    client: paramiko.SSHClient = paramiko.SSHClient()
    client.set_missing_host_key_policy(paramiko.AutoAddPolicy())
    client.connect(hostname=host,
                   username=login,
                   password=password,
                   port=22,
                   look_for_keys=False,
                   allow_agent=False)

    scp = SCPClient(client.get_transport(), progress=progress)
    scp.put('/home/andtokm/Temp/umurmur_1.conf', '/root/umurmur_1.conf')
    scp.put('/home/andtokm/Temp/Docker/arp_scanner_arm64.tar', '/root/arp_scanner_arm641.tar')
    scp.close()


if __name__ == '__main__':
    # connect_test()
    upload_file()
