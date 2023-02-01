from __future__ import annotations
import logging
import socket
import sys
from contextlib import ContextDecorator

import paramiko
from scp import SCPClient


class SSHClient(object):
    SSH_PORT_DEFAULT: int = 22
    RECV_BUFFER_SIZE: int = 65535
    RECV_SOCKET_TIMEOUT: float = 0.5
    ENCODING: str = 'UTF-8'

    class ConnectionContext(ContextDecorator):

        def __init__(self, ssh_client: SSHClient) -> None:
            self.ssh_client: SSHClient = ssh_client

        def __enter__(self):
            self.ssh_client.connect()
            return self

        def __exit__(self, *exc):
            self.ssh_client.close()
            return False

    def __init__(self,
                 hostname: str,
                 username: str = 'root',
                 password: str = 'root',
                 port: int = SSH_PORT_DEFAULT):
        # self.logger = logging.getLogger("SSHClient")

        self.hostname: str = hostname
        self.username: str = username
        self.password: str = password
        self.port: int = port

        # self.status = None

        self.client: paramiko.SSHClient = paramiko.SSHClient()
        self.client.load_system_host_keys()
        self.client.set_missing_host_key_policy(paramiko.AutoAddPolicy())

    # TODO: Refactor
    def connect(self) -> None:
        self.client.connect(hostname=self.hostname,
                            username=self.username,
                            password=self.password,
                            port=self.port,
                            look_for_keys=False,
                            allow_agent=False)

    def close(self) -> None:
        self.client.close()

    def exec(self, cmd: str) -> str:
        with SSHClient.ConnectionContext(self):
            stdin, stdout, stderr = self.client.exec_command(cmd)
            data: str = (stdout.read() + stderr.read()).decode(SSHClient.ENCODING)
            return data

    def exec_shell(self, cmd: str) -> str:
        self.connect()
        output: str = ""
        command: bytes = bytes(f'{cmd}\n', encoding=SSHClient.ENCODING)
        with self.client.invoke_shell() as shell:
            shell.send(command)
            shell.settimeout(self.RECV_SOCKET_TIMEOUT)

            while True:
                try:
                    output += shell.recv(self.RECV_BUFFER_SIZE).decode(SSHClient.ENCODING)
                except socket.timeout:
                    break
        self.close()
        return output

    def upload_file(self, src_file: str, dst_file: str) -> None:
        with SSHClient.ConnectionContext(self), SCPClient(self.client.get_transport()) as scp:
            scp.put(src_file, dst_file)


class Tests:
    host: str = '10.10.10.2'

    @staticmethod
    def execute_cmd_test():
        ssh_client = SSHClient(Tests.host)
        result: str = ssh_client.exec("ls -lar")
        print(result)

    @staticmethod
    def execute_cmd_shell_test():
        ssh_client = SSHClient(Tests.host)
        result: str = ssh_client.exec_shell("ls -lar")
        print(result)

    @staticmethod
    def upload_file_test():
        ssh_client = SSHClient(Tests.host)

        # ssh_client.upload_file('/home/andtokm/DiskS/Temp/TESTING_ROOT_DIR/params.ser', '/root/params1.ser')
        ssh_client.upload_file('/home/andtokm/DiskS/Temp/Docker/csl_sensor_img_arm64.tar',
                               '/root/csl_sensor_img_arm64.tar')


if __name__ == "__main__":
    # Tests.ctx_mgr_test()

    # Tests.execute_cmd_test()
    # Tests.execute_cmd_shell_test()

    Tests.upload_file_test()
