import json
import os
import sys  # TODO: Remove it
import socket
import time
from typing import Dict, Tuple

from utilities.DbModelStatsConverter import DbModelStatsConverter

sys.path.insert(0, os.path.dirname(os.path.realpath(__file__)) + "/..")  # REMOVE

from modules.Service import IService, ServicesPool
from database.model.NetworkGeneral import NetworkGeneral
from database.Database import Database
from sqlalchemy.orm import Session


# ------------------------------------------------------------------------------
# TODO: Move it from here
# ------------------------------------------------------------------------------

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
        print("*** CLOSE CALLED ****")  # REMOVE
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
            print(exc)
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

# ------------------------------------------------------------------------------


class NotificationService(IService):

    def __init__(self):
        IService.__init__(self)
        self.db: Database = Database()
        self.conn_manager: TCPConnectionManger = TCPConnectionManger()
        self.ip: str = "0.0.0.0"
        self.port: int = 52525

    def handler(self) -> None:
        tcp_session: TCPSession = self.conn_manager.get_connection(self.ip, self.port)
        while True:
            with Session(bind=self.db.engine) as session:
                last = session.query(NetworkGeneral).order_by(NetworkGeneral.timestamp.desc()).first()
                stats = DbModelStatsConverter.NetworkGeneral_To_NetworkStats(last)

                # TODO: Refactor this logic???
                # TODO: How much attempts are allowed here?? and so on
                if not tcp_session.send(str(stats)):
                    tcp_session = self.conn_manager.get_connection(self.ip, self.port)
                time.sleep(5)