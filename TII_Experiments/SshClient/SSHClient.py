import logging
import sys

import paramiko
from scp import SCPClient


class SSHClient(object):

    def __init__(self,
                 hostname: str,
                 username: str = 'root',
                 password: str = 'root',
                 port: int = 22):
        self.logger = logging.getLogger("SSHClient")

        self.hostname: str = hostname
        self.username: str = username
        self.password: str = password
        self.port: int = port

        # self.status = None

        self.client: paramiko.SSHClient = paramiko.SSHClient()
        self.client.load_system_host_keys()
        self.client.set_missing_host_key_policy(paramiko.AutoAddPolicy())

    def exec(self, cmd: str):
        self.client.connect(hostname=self.hostname,
                            username=self.username,
                            password=self.password,
                            port=22,
                            look_for_keys=False,
                            allow_agent=False)
        stdin, stdout, stderr = self.client.exec_command(cmd)
        data = stdout.read() + stderr.read()
        self.client.close()

        print(data)

    def exec2(self, cmd: str):
        self.client.connect(hostname=self.hostname,
                            username=self.username,
                            password=self.password,
                            port=22,
                            look_for_keys=False,
                            allow_agent=False)
        shell = self.client.invoke_shell()

        data = shell.send(cmd + '\n')

        buf = ""
        buf += shell.recv(65535).decode()

        shell.close()
        self.client.close()

        print(data)


if __name__ == "__main__":
    ssh_client = SSHClient('192.168.1.5')

    # ssh_client.exec2("pwd")
    # ssh_client.exec("pwd")

    # ssh_client.exec("ls -lar")
