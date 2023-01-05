from __future__ import annotations

import binascii
import socket
import struct
from typing import Tuple, Any


class EthernetHeader(object):
    ETH_HEADED_FORMAT: str = '!6s6sH'

    def __init__(self) -> None:
        self.source_mac = None
        self.destination_mac = None
        self.prototype = None

    @staticmethod
    def create(packet_bytes: bytes) -> EthernetHeader:
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

    def set_source_mac(self, mac_address: str) -> EthernetHeader:
        # self.source_mac = binascii.unhexlify(mac_address.replace(':', ''))
        self.source_mac = self.str_2_mac(mac_address)
        return self

    def set_destination_mac(self, mac_address: str) -> EthernetHeader:
        # self.destination_mac = binascii.unhexlify(mac_address.replace(':', ''))
        self.destination_mac = self.str_2_mac(mac_address)
        return self

    def set_protocol(self, protocol: int) -> EthernetHeader:
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
