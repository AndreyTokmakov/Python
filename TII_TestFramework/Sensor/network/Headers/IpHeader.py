import struct
import socket


class IpHeader(object):

    def __init__(self):
        self.versionAndLen = None # 4bit version 4bit header length
        self.tos = None           # 8bit type of service
        self.totalLen = None      # 16bit total length
        self.identification =None # 16bit header identification
        self.fragment = None      # 16bit others and fragment offset
        self.ttl = None           # 8bit time to live
        self.protocol = None      # 8bit type of protocol
        self.checksum = None      # 16bit header checksum
        self.srcIP = None         # 32bit src IP address
        self.dstIP = None         # 32bit dst IP address

    def decode(self, packet_bytes: bytes) -> None:
        (self.versionAndLen,
         self.tos,
         self.totalLen,
         self.identification,
         self.fragment,
         self.ttl,
         self.protocol,
         self.checksum,
         self.srcIP,
         self.dstIP) = struct.unpack('>BBHHHBBHII', packet_bytes)

    @staticmethod
    def IntToIP(ipInt) -> str:
        return socket.inet_ntoa(struct.pack('I',socket.htonl(ipInt)))

    def __str__(self):
        return ('IP header:\n'
                'Version and Length:{}\n'
                'Type of service:{}\n'
                'Total length:{}\n'
                'Header identification:{}\n'
                'Fragment offset:{}\n'
                'Time to live(TTL):{}\n'
                'Type of protocol:{}\n'
                'Header checksum:{}\n'
                'Source IP address:{}\n'
                'Destination IP address:{}\n'.format(
            self.versionAndLen,
            self.tos,
            self.totalLen,
            self.identification,
            self.fragment,
            self.ttl,
            self.protocol,
            self.checksum,
            self.IntToIP(self.srcIP),
            self.IntToIP(self.dstIP)))