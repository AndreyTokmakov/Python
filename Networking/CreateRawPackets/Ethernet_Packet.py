
from __future__ import annotations
import binascii
import os
# import module
import socket
import struct
import sys
from typing import List, Tuple, Any

import sys  # TODO: Remove it

sys.path.insert(0, os.path.dirname(os.path.realpath(__file__)) + "/../..")

from Networking.Headers.EthernetHeader import EthernetHeader

ETHERNET_HEADER_LEN: int = 14
ETH_P_IP = 0x0800  # Ethernet Protocol packet


# https://www.binarytides.com/python-syn-flood-program-raw-sockets-linux/
# https://www.bitforestinfo.com/blog/01/12/code-ethernet-ii-raw-packet-in-python.html


def create_raw_socket() -> socket:
    # create an INET, raw socket
    try:
        sock: socket = socket.socket(socket.AF_PACKET, socket.SOCK_RAW, socket.ntohs(0x0003))
        return sock
    except socket.error as error:
        print(f'Socket could not be created. Error: {error}')
        sys.exit()


class EthernetHeaderLocal(object):
    ETH_HEADED_FORMAT: str = '!6s6sH'

    def __init__(self,
                 packet_bytes: bytes) -> None:
        header: Tuple[Any] = struct.unpack(EthernetHeaderLocal.ETH_HEADED_FORMAT, packet_bytes)
        self.source_mac: int = header[0]
        self.dest_mac: int = header[1]
        self.prototype = header[2]

    def decode(self, packet_bytes: bytes) -> None:
        (self.source_mac, self.dest_mac, self.prototype) = \
            struct.unpack(EthernetHeaderLocal.ETH_HEADED_FORMAT, packet_bytes)

    @property
    def protocol(self) -> int:
        return socket.ntohs(self.prototype)


class EthHeader(object):
    ETH_HEADED_FORMAT: str = '!6s6sH'

    def __init__(self,
                 dst='11:22:33:44:55:66',
                 src='aa:aa:bb:cc:dd:dd',
                 protocol=ETH_P_IP):
        self.dst = dst  # Destination MAC
        self.src = src  # Source MAC
        self.protocol = protocol  # Protocol Types
        self.raw = None  # Raw Data
        self.assemble_eth_fields()

    def assemble_eth_fields(self):
        self.raw = struct.pack(EthernetHeaderLocal.ETH_HEADED_FORMAT,
                               binascii.unhexlify(self.dst.replace(":", "")),
                               binascii.unhexlify(self.src.replace(":", "")),
                               self.protocol)
        return self.raw


def craft_send_ethernet_packet_test():
    eth_header = EthHeader()

    packet = eth_header.raw

    # ethernet_header: EthernetHeader = EthernetHeader(packet[: ETHERNET_HEADER_LEN])
    # print(ethernet_header.protocol)


def send_ethernet_packet_test_2():
    eth_header = EthHeader()

    packet = eth_header.raw

    sock = create_raw_socket()
    sock.bind(("lo", 0))

    for _ in range(10):
        bytes_send: int = sock.send(packet)
        # print(f'Bytes send: {bytes_send}')


def init_ethernet_packet():
    eth_header = EthernetHeader()
    eth_header.set_destination_mac('11:22:33:44:55:66')\
        .set_source_mac('aa:bb:cc:dd:ee:ff')\
        .set_protocol(ETH_P_IP)

    mac: bytes = struct.pack('6s', eth_header.destination_mac)
    print(mac)

    # binascii.unhexlify(mac_address.replace(':', ''))

    '''    
    packet = eth_header.data

    sock = create_raw_socket()
    sock.bind(("lo", 0))

    for _ in range(10):
        bytes_send: int = sock.send(packet)
    '''


if __name__ == '__main__':
    # craft_send_ethernet_packet_test()
    # send_ethernet_packet_test()
    # send_ethernet_packet_test_2()

    init_ethernet_packet()

    pass
