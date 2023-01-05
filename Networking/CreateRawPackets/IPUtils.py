import socket
import struct
from functools import reduce
from typing import List


#  https://docs.python.org/3/howto/ipaddress.html
class IPUtils(object):

    @staticmethod
    def ip2bytes(ip_address: str) -> bytes:
        return socket.inet_aton(ip_address)

    @staticmethod
    def ip2int(ip_address: str) -> bytes:
        return struct.unpack("!I", IPUtils.ip2bytes(ip_address))[0]

    @staticmethod
    def int2ip(addr) -> str:
        return socket.inet_ntoa(struct.pack("!I", addr))

    @staticmethod
    def Int2IP(ip: int) -> str:
        o1 = int(ip / 16777216) % 256
        o2 = int(ip / 65536) % 256
        o3 = int(ip / 256) % 256
        o4 = int(ip) % 256
        return '%(o1)s.%(o2)s.%(o3)s.%(o4)s' % locals()

    @staticmethod
    def IP2Int(ip_address: str) -> int:
        octets: List = [int(v) for v in ip_address.split('.')]
        res: int = (16777216 * octets[0]) + (65536 * octets[1]) + (256 * octets[2]) + octets[3]
        return res

    @staticmethod
    def IP2Int_2(ip_address: str) -> int:
        octets: List = [int(v) for v in ip_address.split('.')]
        return octets[3] | octets[2] << 8 | octets[1] << 16 | octets[0] << 24

    @staticmethod
    def IP2Int_3(ip_address: str) -> int:
        return reduce(lambda x, y: x * 256 + y, [int(v) for v in ip_address.split('.')])
