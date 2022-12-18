import struct
import socket


class IPHeader(object):
    IP_HEADED_FORMAT: str = '>BBHHHBBHII'

    def __init__(self, buff: bytes) -> None:
        header = struct.unpack(IPHeader.IP_HEADED_FORMAT, buff)
        self.ver: int = header[0] >> 4
        self.ihl: int = header[0] & 0xF
        self.tos: int = header[1]
        self.totalLen: int = header[2]
        self.id: int = header[3]
        self.offset: int = header[4]
        self.ttl: int = header[5]
        self.protocol: int = header[6]
        self.checksum = header[7]
        self.src = header[8]
        self.dst = header[9]

    def decode(self, packet_bytes: bytes) -> None:
        (self.ver,
         self.tos,
         self.totalLen,
         self.id,
         self.offset,
         self.ttl,
         self.protocol,
         self.checksum,
         self.src,
         self.dst) = struct.unpack(IPHeader.IP_HEADED_FORMAT, packet_bytes)

        self.ihl = self.ver & 0xF
        self.ver = self.ver >> 4

    @staticmethod
    def IntToIP(ip: int) -> str:
        return socket.inet_ntoa(struct.pack('I', socket.htonl(ip)))

    @property
    def sourceIpAsStr(self) -> str:
        return IPHeader.IntToIP(self.src)

    @property
    def destIpAsStr(self) -> str:
        return IPHeader.IntToIP(self.src)

    @property
    def ipHeaderLength(self) -> int:
        return self.ihl * 4
