import sys  # TODO: Remove it

sys.path.append('/home/andtokm/DiskS/ProjectsUbuntu/Python/TII_TestFramework/Sensor')

import datetime
import socketserver
import threading
import time
from typing import Tuple, Callable

from sqlalchemy import select

from http.server import BaseHTTPRequestHandler, HTTPServer

from sqlalchemy.orm import Session
from database.model.NetworkGeneral import NetworkGeneral
from database.Database import Database


class State(object):

    def __init__(self):
        self.timestamp: datetime.datetime = datetime.datetime.now()
        self.records_count: int = 0
        self.table = []


class RequestHandler(BaseHTTPRequestHandler):

    def __init__(self,
                 request: bytes,
                 client_address: Tuple[str, int],
                 server: socketserver.BaseServer):
        super().__init__(request, client_address, server)

    def __get_body(self, path):
        print(f'')
        return f"""
            <html><head><title>WebGateway [Debug]</title></head>
            <body bgcolor='gray'>
            <p>This is an example web server.</p>
            <p>Request: {path}</p>
            <p>Timestamp: { self.server.state.timestamp}</p>
            <p>Count: { self.server.state.records_count}</p>
            </body>
            </html>
        """

    def do_GET(self):
        self.send_response(200)
        self.send_header("Content-type", "text/html")
        self.end_headers()
        self.wfile.write(bytes(self.__get_body(self.path), "utf-8"))


class WebGatewayServer(HTTPServer):

    def __init__(self,
                 server_address: Tuple[str, int],
                 request_handler_class: Callable,
                 bind_and_activate: bool = True):
        super().__init__(server_address, request_handler_class, bind_and_activate)
        self.state: State = State()
        self.updater_thread: threading.Thread = threading.Thread(target=self.update_data,
                                                                 args=())
        self.db: Database = Database()

    def update_data(self):
        while True:
            self.state.timestamp = datetime.datetime.now()
            self.select_where_block()
            time.sleep(1)

    def select_where_block(self):
        start_from: datetime.datetime = datetime.datetime(1970, 1, 1, tzinfo=datetime.timezone.utc) \
            if len(self.state.table) == 0 else self.state.table[-1].timestamp

        # print(f"{self.state.timestamp}: select_where_block")
        with Session(bind=self.db.engine) as session:
            stmt = select([NetworkGeneral.__table__]).where(NetworkGeneral.timestamp > start_from) \
                .limit(WebGateway.BLOCK_SIZE).order_by(NetworkGeneral.timestamp)
            result = session.execute(stmt)
            result_set = result.fetchall()
            for entry in result_set:
                self.state.table.append(entry)

            self.state.records_count += len(result_set)

    def serve_forever(self, poll_interval=0.5):
        self.updater_thread.start()
        return super().serve_forever(poll_interval)

    def finish_request(self, request, client_address):
        """Finish one request by instantiating RequestHandlerClass."""
        self.RequestHandlerClass(request, client_address, self)

    def start(self):
        try:
            print(f"Server started http://{self.server_address[0]}:{self.server_address[1]}")
            self.serve_forever()
        except KeyboardInterrupt:
            pass

    def __repr__(self) -> str:
        return f'WebGatewayServer [{self.state.timestamp}]'


def main():
    server = WebGatewayServer(("127.0.0.1", 8080), RequestHandler)
    server.start()
    # server.server_close()


class WebGateway(object):
    BLOCK_SIZE: int = 5

    def __init__(self):
        self.db: Database = Database()
        self.table = []

    def select(self):
        with Session(bind=self.db.engine) as session:
            last = session.query(NetworkGeneral).order_by(NetworkGeneral.timestamp.desc()).first()
            print('NetworkStats ['
                  f'\n\tpackets_total: {last.total}'
                  f'\n\ticmp_packets: {last.icmp}'
                  f'\n\ttcp_packets: {last.tcp}'
                  f'\n\tudp_packets: {last.udp}'
                  '\n]')

    def select_where_blocks_all(self):
        start_from: datetime.datetime = datetime.datetime(1970, 1, 1, tzinfo=datetime.timezone.utc)

        with Session(bind=self.db.engine) as session:
            count: int = 1
            while count > 0:
                stmt = select([NetworkGeneral.__table__]) \
                    .where(NetworkGeneral.timestamp > start_from) \
                    .limit(WebGateway.BLOCK_SIZE) \
                    .order_by(NetworkGeneral.timestamp)
                result = session.execute(stmt)
                result_set = result.fetchall()
                count = len(result_set)

                for entry in result_set:
                    self.table.append(entry)

                start_from = self.table[-1].timestamp

    def select_where_block(self):
        start_from: datetime.datetime = datetime.datetime(1970, 1, 1, tzinfo=datetime.timezone.utc) \
            if len(self.table) == 0 else self.table[-1].timestamp

        with Session(bind=self.db.engine) as session:
            stmt = select([NetworkGeneral.__table__]).where(NetworkGeneral.timestamp > start_from) \
                .limit(WebGateway.BLOCK_SIZE).order_by(NetworkGeneral.timestamp)
            result = session.execute(stmt)
            for entry in result.fetchall():
                self.table.append(entry)


if __name__ == '__main__':
    main()