import socket
import struct
import sys
import time
from typing import Tuple

# iface_name: str = 'wlp0s20f3'
iface_name: str = 'lo'


def create_raw_socket() -> socket:
    # create an INET, raw socket
    try:
        sock: socket = socket.socket(socket.AF_PACKET, socket.SOCK_RAW, socket.ntohs(0x0003))
        return sock
    except socket.error as error:
        print(f'Socket could not be created. Error: {error}')
        sys.exit()


def socket_read_timeout_test():
    sock: socket = create_raw_socket()
    sock.bind((iface_name, 0))
    max_timeout: float = 5.0

    # sock.settimeout(1.0)

    timeval = struct.pack('ll', 0, 100000)  # 0.5 sec
    sock.setsockopt(socket.SOL_SOCKET, socket.SO_RCVTIMEO, timeval)

    start: time.time = time.time()
    while True:
        try:
            recv: Tuple = sock.recvfrom(65565)
            packet: bytes = recv[0]
            print("got some")
        except:
            pass

        if (time.time() - start) >= max_timeout:
            break

    print(time.time() - start)


if __name__ == "__main__":
    socket_read_timeout_test()
    pass
