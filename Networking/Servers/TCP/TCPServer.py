from __future__ import annotations

import socket
import socketserver

HOST, PORT = "0.0.0.0", 50080


class MyTCPHandler(socketserver.BaseRequestHandler):

    def __init__(self,
                 request: _RequestType,
                 client_address: _AddressType,
                 server: BaseServer):
        super().__init__(request, client_address, server)
        print("MyTCPHandler()")

    def handle(self):
        # self.request is the TCP socket connected to the client
        self.data = self.request.recv(1024).strip()
        print(f"{self.client_address[0]} wrote: {self.data}")
        # just send back the same data, but upper-cased
        self.request.sendall(self.data.upper())


def run_server_1():
    with socketserver.TCPServer((HOST, PORT), MyTCPHandler) as server:
        server.serve_forever()


def run_socker_server():
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)

    server_address = (HOST, 50080)
    print('Starting up on {} port {}'.format(*server_address))
    sock.bind(server_address)

    # Listen for incoming connections
    sock.listen(1)

    while True:
        connection, client_address = sock.accept()
        try:
            print('connection from', client_address)
            while True:  # Read the data in small chunks and retransmit it
                data: bytes = connection.recv(64)
                request: str = data.decode('utf-8')
                if data:
                    # print('sending data back to the client')
                    connection.sendall(bytes(f'[{request}]', 'utf-8'))
                else:
                    print('no data from', client_address)
                    break
        finally:  # Clean up the connection
            connection.close()


def stats_collector_server():
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    sock.bind((HOST, 52525))
    sock.listen(1)

    print(f'Starting up on {HOST}: 52525')
    while True:
        connection, client_address = sock.accept()
        try:
            print('connection from', client_address)
            while True:  # Read the data in small chunks and retransmit it
                data: bytes = connection.recv(1024)
                request: str = data.decode('utf-8')
                if data:
                    print(request)
                else:
                    print('no data from', client_address)
                    break
        finally:  # Clean up the connection
            connection.close()


if __name__ == "__main__":
    # run_server_1()
    # run_socker_server()
    stats_collector_server()

