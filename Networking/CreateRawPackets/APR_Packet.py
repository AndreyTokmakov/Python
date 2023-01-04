from __future__ import annotations

import binascii
import ipaddress
import os
import socket
import struct
from functools import reduce
from typing import List, Tuple, Any

import sys  # TODO: Remove it

sys.path.insert(0, os.path.dirname(os.path.realpath(__file__)) + "/../..")

from Networking.Headers.EthernetHeader import EthernetHeader

ETHERNET_HEADER_LEN: int = 14
TCP_HEADER_LEN: int = 20

ETH_P_LOOP = 0x0060  # Ethernet Loopback packet
ETH_P_PUP = 0x0200  # Xerox PUP packet
ETH_P_PUPAT = 0x0201  # Xerox PUP Addr Trans packet
ETH_P_TSN = 0x22F0  # TSN (IEEE 1722) packet
ETH_P_ERSPAN2 = 0x22EB  # ERSPAN version 2 (type III)
ETH_P_IP = 0x0800  # Internet Protocol packet
ETH_P_X25 = 0x0805  # CCITT X.25
ETH_P_ARP = 0x0806  # Address Resolution packet
ETH_P_BPQ = 0x08FF  # G8BPQ AX.25 Ethernet Packet	[ NOT AN OFFICIALLY REGISTERED ID ]
ETH_P_IEEEPUP = 0x0a00  # Xerox IEEE802.3 PUP packet
ETH_P_IEEEPUPAT = 0x0a01  # Xerox IEEE802.3 PUP Addr Trans packet
ETH_P_BATMAN = 0x4305  # B.A.T.M.A.N.-Advanced packet [ NOT AN OFFICIALLY REGISTERED ID ]
ETH_P_DEC = 0x6000  # DEC Assigned proto
ETH_P_DNA_DL = 0x6001  # DEC DNA Dump/Load
ETH_P_DNA_RC = 0x6002  # DEC DNA Remote Console
ETH_P_DNA_RT = 0x6003  # DEC DNA Routing
ETH_P_LAT = 0x6004  # DEC LAT
ETH_P_DIAG = 0x6005  # DEC Diagnostics
ETH_P_CUST = 0x6006  # DEC Customer use
ETH_P_SCA = 0x6007  # DEC Systems Comms Arch
ETH_P_TEB = 0x6558  # Trans Ether Bridging
ETH_P_RARP = 0x8035  # Reverse Addr Res packet
ETH_P_ATALK = 0x809B  # Appletalk DDP
ETH_P_AARP = 0x80F3  # Appletalk AARP
ETH_P_8021Q = 0x8100  # 802.1Q VLAN Extended Header
ETH_P_ERSPAN = 0x88BE  # ERSPAN type II
ETH_P_IPX = 0x8137  # IPX over DIX
ETH_P_IPV6 = 0x86DD  # IPv6 over bluebook
ETH_P_PAUSE = 0x8808  # IEEE Pause frames. See 802.3 31B
ETH_P_SLOW = 0x8809  # Slow Protocol. See 802.3ad 43B
ETH_P_WCCP = 0x883E  # Web-cache coordination protocol


class ARPHeader(object):
    ARP_HEADED_FORMAT: str = '!HHBBH6s4s6s4s'

    # TODO : Check size of types in Python
    # FIXME: Replace call 'binascii.unhexlify('00:00:00:00:00:00')'
    # FIXME: Replace call 'socket.inet_aton("0.0.0.0")'
    def __init__(self) -> None:

        # TODO: handle default in the different way?
        self.htype: int = 1         # Hardware type (16 bits): 1 for ethernet
        self.ptype: int = ETH_P_IP  # Internet Protocol packet
        self.hlen: int = 6          # Hardware address length (8 bits): 6 bytes for MAC address
        self.plen: int = 4          # Protocol address length (8 bits): 4 bytes for IPv4 address
        self.opcode: int = 1        # 1=request / 2=reply

        self.sender_mac: bytes = ARPHeader.str_2_mac('00:00:00:00:00:00')  # TODO: or just use INT (0) --> Bytes
        self.sender_ip: bytes = ARPHeader.str_2_ip("0.0.0.0")  # TODO: or just use INT (0) --> Bytes
        self.target_mac: bytes = ARPHeader.str_2_mac('00:00:00:00:00:00')  # TODO: or just use INT (0) --> Bytes
        self.target_ip: bytes = ARPHeader.str_2_ip("0.0.0.0")  # TODO: or just use INT (0) --> Bytes

    @staticmethod
    def create(packet_bytes: bytes) -> ARPHeader:
        header: Tuple[Any] = struct.unpack(ARPHeader.ARP_HEADED_FORMAT, packet_bytes)

        arp: ARPHeader = ARPHeader()
        arp.htype = header[0]
        arp.ptype = header[1]
        arp.hlen = header[2]
        arp.plen = header[3]
        arp.opcode = header[4]
        arp.sender_mac = header[5]
        arp.sender_ip = header[6]
        arp.target_mac = header[7]
        arp.target_ip = header[8]
        return arp

    # TODO: Check
    def decode(self, packet_bytes: bytes) -> None:
        (self.htype, self.ptype, self.hlen, self.plen, self.opcode,
         self.sender_mac, self.sender_ip, self.target_mac, self.target_ip) = \
            struct.unpack(ARPHeader.ARP_HEADED_FORMAT, packet_bytes)

    @staticmethod
    def str_2_ip(ip_address: str) -> bytes:
        return socket.inet_aton(ip_address)

    @staticmethod
    def str_2_mac(mac_address: str) -> bytes:
        return binascii.unhexlify(mac_address.replace(':', ''))

    def set_sender_ip(self, ip_address: str) -> ARPHeader:
        self.sender_ip = ARPHeader.str_2_ip(ip_address)
        return self

    def set_target_ip(self, ip_address: str) -> ARPHeader:
        self.target_ip = ARPHeader.str_2_ip(ip_address)
        return self

    def set_sender_mac(self, mac_address: str) -> ARPHeader:
        self.sender_mac = ARPHeader.str_2_mac(mac_address)
        return self

    def set_target_mac(self, mac_address: str) -> ARPHeader:
        self.target_mac = ARPHeader.str_2_mac(mac_address)
        return self

    @property
    def data(self):
        return struct.pack(ARPHeader.ARP_HEADED_FORMAT,
                           self.htype,
                           self.ptype,
                           self.hlen,
                           self.plen,
                           self.opcode,
                           self.sender_mac,
                           self.sender_ip,
                           self.target_mac,
                           self.target_ip)

    # TODO: implement __repr__() ??

    '''
    @property
    def protocol(self) -> int:
        return socket.ntohs(self.prototype)
    '''

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



# https://www.binarytides.com/python-syn-flood-program-raw-sockets-linux/
# https://www.bitforestinfo.com/blog/01/12/code-ethernet-ii-raw-packet-in-python.html

# https://stackoverflow.com/questions/55203086/how-to-use-raw-socket-send-and-receive-arp-package-in-python

# BROADCAST
# https://docs.python.org/3/library/socket.html


def pack(byte_sequence: List):
    """ Convert list of bytes to byte string. """
    return b"".join(map(bytes, byte_sequence))


def create_raw_socket() -> socket:
    # create an INET, raw socket
    try:
        sock: socket = socket.socket(socket.AF_PACKET, socket.SOCK_RAW, socket.ntohs(0x0003))
        return sock
    except socket.error as error:
        print(f'Socket could not be created. Error: {error}')
        sys.exit()


def send_arp_packet_test():
    src_mac, dst_mac = 'a8:93:4a:4e:00:6b', 'ff:ff:ff:ff:ff:ff'
    source_ip = "192.168.0.184"  # sender ip address
    dest_ip = "192.168.0.118"  # target ip address

    eth_header = EthernetHeader().set_destination_mac(dst_mac) \
        .set_source_mac(src_mac).set_protocol(ETH_P_ARP)

    # ARP header
    htype = 1  # Hardware_type ethernet
    ptype = ETH_P_IP  # Internet Protocol packet
    hlen = 6  # Hardware address Len
    plen = 4  # Protocol addr. len
    operation = 1  # 1=request / 2=reply
    src_ip = socket.inet_aton(source_ip)
    dst_ip = socket.inet_aton(dest_ip)
    arp_hdr = struct.pack("!HHBBH6s4s6s4s",
                          htype, ptype, hlen, plen, operation,
                          eth_header.source_mac, src_ip,
                          # eth_header.destination_mac,
                          binascii.unhexlify('000000000000'),
                          dst_ip)

    packet = eth_header.data + arp_hdr

    sock = create_raw_socket()
    sock.bind(("wlp4s0", 0))

    for _ in range(10):
        sock.send(packet)


def send_arp_packet_test_2():
    src_mac, dst_mac = 'bc:6e:e2:03:74:ba', 'ff:ff:ff:ff:ff:ff'
    source_ip = "192.168.57.54"  # sender ip address: OUR interface IP address
    dest_ip = "192.168.57.17"  # target ip address

    eth_header = EthernetHeader().set_destination_mac(dst_mac) \
        .set_source_mac(src_mac).set_protocol(ETH_P_ARP)

    arp = ARPHeader()
    arp.htype = 1  # Hardware type (16 bits): 1 for ethernet
    arp.ptype = ETH_P_IP  # Internet Protocol packet
    arp.hlen = 6  # Hardware address length (8 bits): 6 bytes for MAC address
    arp.plen = 4  # Protocol address length (8 bits): 4 bytes for IPv4 address
    arp.opcode = 1  # 1=request / 2=reply

    # arp.sender_ip = socket.inet_aton(source_ip)
    # arp.sender_mac = eth_header.source_mac
    # arp.target_ip = socket.inet_aton(dest_ip)

    arp.set_sender_ip(source_ip)
    arp.set_target_ip(dest_ip)
    arp.set_sender_mac(src_mac)

    packet = eth_header.data + arp.data

    sock = create_raw_socket()
    sock.bind(("wlp0s20f3", 0))

    for _ in range(1):
        sock.send(packet)


def apr_scan():
    src_mac, dst_mac = 'bc:6e:e2:03:74:ba', 'ff:ff:ff:ff:ff:ff'
    source_ip = "192.168.57.54"  # sender ip address: OUR interface IP address
    dest_ip_start: int = IPUtils.IP2Int_2("192.168.1.0")

    sock = create_raw_socket()
    sock.bind(("wlp0s20f3", 0))

    eth_hdr: EthernetHeader = EthernetHeader().set_destination_mac(dst_mac) \
        .set_source_mac(src_mac).set_protocol(ETH_P_ARP)

    arp_hdr = ARPHeader()
    arp_hdr.set_sender_ip(source_ip)
    arp_hdr.set_sender_mac(src_mac)

    for i in range(256):
        target_id: str = IPUtils.Int2IP(dest_ip_start + i)
        arp_hdr.set_target_ip(target_id)
        packet: bytes = eth_hdr.data + arp_hdr.data
        sock.send(packet)


def apr_header_fields_test():
    src_mac, dst_mac = 'bc:6e:e2:03:74:ba', 'ff:ff:ff:ff:ff:ff'
    source_ip: str = "192.168.57.54"  # sender ip address: OUR interface IP address
    dest_ip = "192.168.57.17"  # target ip address

    arp = ARPHeader()

    arp.htype = 1  # Hardware type (16 bits): 1 for ethernet
    arp.ptype = ETH_P_IP  # Internet Protocol packet
    arp.hlen = 6  # Hardware address length (8 bits): 6 bytes for MAC address
    arp.plen = 4  # Protocol address length (8 bits): 4 bytes for IPv4 address
    arp.opcode = 1  # 1=request / 2=reply
    arp.sender_ip = socket.inet_aton(source_ip)
    arp.sender_mac = binascii.unhexlify(src_mac.replace(':', ''))
    arp.target_ip = socket.inet_aton(dest_ip)

    print(f'htype = {arp.htype}')


def utils_test():
    # print(type(0xc0a80164))
    # print(type(167772161))

    ip_str: str = '192.168.1.2'
    ip_int: int = 3232235778
    ip_hex: int = 0xc0a80102

    print(IPUtils.int2ip(ip_hex))         # 192.168.1.100
    print(IPUtils.Int2IP(ip_hex))         # 192.168.1.100
    print(IPUtils.Int2IP(ip_int))         # 192.168.1.100
    print(ipaddress.IPv4Address(ip_int))  # 192.168.1.100

    print()

    print(IPUtils.ip2int(ip_str))    # 3232235778
    print(IPUtils.IP2Int(ip_str))    # 3232235778
    print(IPUtils.IP2Int_2(ip_str))  # 3232235778
    print(IPUtils.IP2Int_3(ip_str))  # 3232235778
    print(int(ipaddress.IPv4Address(ip_str)))  # 3232235778

    print()

    print(IPUtils.ip2bytes(ip_str))  # b'\xc0\xa8\x01\x02'


if __name__ == '__main__':
    # create_raw_socket()
    # ethernet_packet_test()

    # send_arp_packet_test()
    # send_arp_packet_test_2()

    apr_scan()

    # apr_header_fields_test()

    # utils_test()
