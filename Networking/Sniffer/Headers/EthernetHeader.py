import socket
import struct


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
