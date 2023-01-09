import socket
import time
from collections import defaultdict
from typing import Dict, Tuple


# TODO: Shall it be auto_closable?
class TCPSession(object):
    MAX_RETRIES_ATTEMPTS: int = 5

    def __init__(self,
                 ip: str = "127.0.0.1",
                 port: int = 0,
                 connected: bool = False):
        self.host_ip_address: str = ip
        self.port: int = port
        self.connected: bool = connected
        self.retries: int = 0
        self.timeout_sec: int = 1
        self.sock: socket.socket = None
        # print(f"{self} created")

    def __str__(self) -> str:
        return f"TCPSession({self.host_ip_address}:{self.port}, Connected: {self.connected})"

    def __repr__(self) -> str:
        return str(self)

    def close(self) -> None:
        self.connected = False
        self.retries = 0
        self.timeout_sec = 1
        self.sock.close()
        self.sock = None

    def send(self, buffer: str) -> bool:
        try:
            self.sock.sendall(bytes(buffer, "utf-8"))
            return True
        except Exception as exc:
            self.close()
            return False


class TCPConnectionManger(object):
    __instance = None
    __connection_table: Dict[Tuple, TCPSession] = {}

    def __new__(cls):
        if cls.__instance is None:
            cls.__instance = super().__new__(cls)
        return cls.__instance

    def get_connection(self, ip: str, port: int) -> TCPSession:  # socket.socket:
        key: Tuple = (ip, port)
        session: TCPSession = self.__connection_table.get(key)
        if session is None:
            session = TCPSession(ip, port)
            self.__connection_table[key] = session

        if session.sock is None:
            TCPConnectionManger.__init_session(session)

        return session

    @staticmethod
    def __init_session(session: TCPSession) -> bool:
        session.sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        while True:
            try:
                session.sock.connect((session.host_ip_address, session.port))
                return True
            except ConnectionRefusedError:
                session.timeout_sec *= 2
                session.retries += 1
                if TCPSession.MAX_RETRIES_ATTEMPTS <= session.retries:
                    return False
                time.sleep(session.timeout_sec)


'''
class TCPConnectionManger2(object):
    instance = None

    def __new__(cls):
        if cls.instance is None:
            cls.instance = super().__new__(cls)
        return cls.instance

    def __init__(self):
        self.__connection_table: Dict[Tuple, TCPSession] = defaultdict(TCPSession)

    def get_connection(self,
                       ip: str = "127.0.0,1",
                       port: int = 0) -> TCPSession:  # socket.socket:
        session: TCPSession = self.__connection_table[(ip, port)]
        return session
'''


class Tests:

    @staticmethod
    def send_request():
        data = "{\"type\": \"request\", \"data\": \"Hello world!\"}"

        # Create a socket (SOCK_STREAM means a TCP socket)
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
            # Connect to server and send data
            sock.connect(("0.0.0.0", 52525))
            sock.sendall(bytes(data + "\n", "utf-8"))

        print("Sent:     {}".format(data))

    @staticmethod
    def is_same_session():

        session1: TCPSession = TCPConnectionManger().get_connection("0.0.0.0", 52525)
        session2: TCPSession = TCPConnectionManger().get_connection("0.0.0.0", 52525)

        assert session1 == session2
        assert session1 is session2

        print(session1)
        print(session2)


if __name__ == "__main__":
    mgr = TCPConnectionManger()
    for idx in range(10):
        session = mgr.get_connection("0.0.0.0", 52525)
        result: bool = session.send(f'Hello_{idx}')
        print(result)
        time.sleep(1)

    # Tests.is_same_session()
