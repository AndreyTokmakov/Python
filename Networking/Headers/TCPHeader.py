import struct


class TCPHeader(object):
    TCP_HEADED_FORMAT: str = '!HHLLBBHHH'

    def __init__(self,
                 packet_bytes: bytes) -> None:
        header: bytes = struct.unpack(TCPHeader.TCP_HEADED_FORMAT, packet_bytes)

        self.source_port: int = header[0]
        self.dest_port: int = header[1]
        self.sequence = header[2]
        self.acknowledgement = header[3]
        self.offset = header[4]
        self.flags = header[5]
        self.window = header[6]
        self.checksum = header[7]
        self.urgent_ptr = header[8]

    @property
    def dataOffset(self) -> int:
        return (self.offset >> 4) * 4

    def decode(self,
               packet_bytes: bytes) -> None:
        (self.source_port,
         self.dest_port,
         self.sequence,
         self.acknowledgement,
         self.offset,
         self.flags,
         self.window,
         self.checksum,
         self.urgent_ptr) = struct.unpack(TCPHeader.TCP_HEADED_FORMAT, packet_bytes)

    '''
    @staticmethod
    def IntToIP(ip: int) -> str:
        return socket.inet_ntoa(struct.pack('I', socket.htonl(ip)))

    @property
    def sourceIpAsStr(self) -> str:
        return IPHeader2.IntToIP(self.src)

    @property
    def destIpAsStr(self) -> str:
        return IPHeader2.IntToIP(self.src)
    '''
