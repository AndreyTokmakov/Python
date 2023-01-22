import binascii
import socket
import struct
from typing import Tuple, Any

import six

ETHERNET_HEADER_LEN: int = 14
ARP_TYPE: int = socket.ntohs(0x0806)
BATMAN_TYPE: int = socket.ntohs(0x4305)



class EthernetHeader(object):
    ETH_HEADED_FORMAT: str = '!6s6sH'

    def __init__(self) -> None:
        self.source_mac = None
        self.destination_mac = None
        self.prototype = None

    @staticmethod
    def create(packet_bytes: bytes):
        header: Tuple[Any] = struct.unpack(EthernetHeader.ETH_HEADED_FORMAT, packet_bytes)

        eth: EthernetHeader = EthernetHeader()
        eth.source_mac = header[0]
        eth.destination_mac = header[1]
        eth.prototype = header[2]

        return eth

    def decode(self, packet_bytes: bytes) -> None:
        (self.source_mac, self.destination_mac, self.prototype) = \
            struct.unpack(EthernetHeader.ETH_HEADED_FORMAT, packet_bytes)

    # TODO: Check for performance [find and use fastest implementation]
    @staticmethod
    def str_2_mac(mac_address: str) -> bytes:
        return binascii.unhexlify(mac_address.replace(':', ''))

    # TODO: Check for performance [find and use fastest implementation]
    # TODO: Implementation requires 'import six' .. it should not be here
    @staticmethod
    def mac_2_str(mac: bytes) -> str:
        return ':'.join('%02x' % i for i in six.iterbytes(mac))

    def set_source_mac(self, mac_address: str):
        # self.source_mac = binascii.unhexlify(mac_address.replace(':', ''))
        self.source_mac = self.str_2_mac(mac_address)
        return self

    def set_destination_mac(self, mac_address: str):
        # self.destination_mac = binascii.unhexlify(mac_address.replace(':', ''))
        self.destination_mac = self.str_2_mac(mac_address)
        return self

    def set_protocol(self, protocol: int):
        self.prototype = protocol
        return self

    @property
    def data(self):
        return struct.pack(EthernetHeader.ETH_HEADED_FORMAT,
                           self.destination_mac,
                           self.source_mac,
                           self.prototype)

    @property
    def protocol(self) -> int:
        return socket.ntohs(self.prototype)


def dump_ogm_messages() -> None:
    # create an INET, raw socket
    sock: socket = socket.socket(socket.AF_PACKET, socket.SOCK_RAW, socket.ntohs(0x0003))

    # receive a packet
    while True:
        recv: Tuple = sock.recvfrom(65565)
        packet: bytes = recv[0]
        ethernet_header: EthernetHeader = EthernetHeader.create(packet[: ETHERNET_HEADER_LEN])

        if ethernet_header.protocol == BATMAN_TYPE:
            (type, version, ttl, flags, seqno, orig, prev_sender, reserved, tq, tvlv_len) = \
                struct.unpack('>BBBBI6s6sBBH', packet[ETHERNET_HEADER_LEN: 24 + ETHERNET_HEADER_LEN])
            print('BATMAN: ', type, version, ttl, seqno,
                  EthernetHeader.mac_2_str(orig), EthernetHeader.mac_2_str(prev_sender),
                  reserved, tq, tvlv_len)


if __name__ == '__main__':
    dump_ogm_messages()
