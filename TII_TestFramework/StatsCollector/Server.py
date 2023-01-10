import datetime
import json
import socket
from typing import Dict

from database.model.NetworkGeneral import NetworkGeneral
from database.Database import Database
from sqlalchemy.orm import Session


class Server(object):

    def __init__(self):
        self.host: str = "0.0.0.0"
        self.port: int = 52525
        self.database: Database = Database()

    # FIXME: Move somewhere else
    def start_up(self):
        Database.validate(self.database)

    def start_server(self):
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

    def handle_request(self, request: str):
        print(request)
        request: Dict = json.loads(request)

        timestamp: str = request['timestamp']
        total: int = int(request['packets_total'])
        tcp: int = int(request['tcp_packets'])
        udp: int = int(request['udp_packets'])
        icmp: int = int(request['icmp_packets'])

        print(timestamp, total, tcp, udp, icmp)

        # TODO: we may need to have some additional logic here
        # stats: NetworkGeneral = DbModelStatsConverter.NetworkStats_To_NetworkGeneral(delta)

        stats: NetworkGeneral = NetworkGeneral(timestamp=datetime.datetime.utcnow(),  # FIXME
                                               total=total,
                                               icmp=icmp,
                                               tcp=tcp,
                                               udp=udp)

        with Session(bind=self.database.engine) as session:
            session.add_all([stats])
            session.commit()


if __name__ == "__main__":
    server = Server()
    server.start_up()
    server.start_server()
