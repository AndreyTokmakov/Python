from __future__ import annotations

import binascii
import socket
import struct
from typing import Tuple, Any

'''
class EthernetHeader(object):
    ETH_HEADED_FORMAT: str = '!6s6sH'

    def __init__(self,
                 packet_bytes: bytes) -> None:
        header: bytes = struct.unpack(EthernetHeader.ETH_HEADED_FORMAT, packet_bytes)
        self.source_mac: int = header[0]
        self.dest_mac: int = header[1]
        self.prototype = header[2]

    def decode(self,
               packet_bytes: bytes) -> None:
        (self.source_mac, self.dest_mac, self.prototype) = \
            struct.unpack(EthernetHeader.ETH_HEADED_FORMAT, packet_bytes)

    @property
    def protocol(self) -> int:
        return socket.ntohs(self.prototype)
'''


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

    def set_source_mac(self, mac: str) -> EthernetHeader:
        self.source_mac = binascii.unhexlify(mac.replace(':', ''))
        return self

    def set_destination_mac(self, mac: str) -> EthernetHeader:
        self.destination_mac = binascii.unhexlify(mac.replace(':', ''))
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
