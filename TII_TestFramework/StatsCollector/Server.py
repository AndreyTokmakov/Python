
import os
import sys  # TODO: Remove it

sys.path.insert(0, os.path.dirname(os.path.realpath(__file__)))
sys.path.insert(0, os.path.dirname(os.path.realpath(__file__)) + "/..")


import datetime
import json
import socket
from multiprocessing import Process
from typing import Dict

from StatsCollector.statistics.NetworkStats import NetworkStats
from web_gateway.web_gateway import start_web_server
from database.model.NetworkGeneral import NetworkGeneral
from database.Database import Database
from sqlalchemy.orm import Session


# TODO: Add LOGGING
class Server(object):

    def __init__(self):
        self.host: str = "0.0.0.0"
        self.port: int = 52525
        self.database: Database = Database()
        self.server_process: Process = None

    # FIXME: Move somewhere else
    def validate(self) -> bool:
        Database.validate(self.database)
        # TODO: Some checks??
        return True

    # TODO: Make process a Daemon?
    def start_server(self):
        if not self.validate():
            return  False

        self.server_process = Process(target=self.run, args=())
        self.server_process.start()
        # TODO: Some checks??
        return True

    def run(self):
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.bind((self.host, self.port))
        sock.listen(1)

        print(f'Starting up on {self.host}:{self.port}')
        while True:
            connection, client_address = sock.accept()
            try:
                # print('connection from', client_address)
                while True:  # Read the data in small chunks and retransmit it
                    data: bytes = connection.recv(1024)
                    request: str = data.decode('utf-8')
                    if data:
                        self.handle_request(request)
                    else:
                        # print('no data from', client_address)
                        break
            finally:  # Clean up the connection
                connection.close()

    # TODO: Here shall be all request processing starts
    # TODO: Request JSON
    #     {
    #       'type': 'network_stat',
    #       'ip': '192.168.1.5',
    #       'data': '{}'
    #     }
    def handle_request(self, request: str):
        request: Dict = json.loads(request)

        # TODO: FixMe: On the sender side: request['data'] should be a DICT with out json.loads
        data: Dict = json.loads(request['data'])

        # TODO: we may need to have some additional logic here
        stats: NetworkStats = NetworkStats()
        stats.total = data['packets_total']
        stats.tcp = data['tcp_packets']
        stats.udp = data['udp_packets']
        stats.icmp = data['icmp_packets']

        # TODO: Fixme
        # stats.timestamp = int(data['timestamp'])
        stats.timestamp = datetime.datetime.utcnow()

        # FIXME: 'timestamp' shall be obtained from the request JSON
        # TODO: Add conversation from NetworkStats <---> NetworkGeneral
        stats: NetworkGeneral = NetworkGeneral(timestamp=datetime.datetime.utcnow(),  # FIXME
                                               total=stats.total,
                                               icmp=stats.icmp,
                                               tcp=stats.tcp,
                                               udp=stats.udp)

        with Session(bind=self.database.engine) as session:
            session.add_all([stats])
            session.commit()


# TODO: Make non-blocking

if __name__ == "__main__":
    server = Server()
    server.start_server()

    start_web_server()
