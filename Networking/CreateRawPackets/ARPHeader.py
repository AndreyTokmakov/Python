from __future__ import annotations

import binascii
import socket
import struct
from typing import Tuple, Any

import six

# TODO: Move to ENUM ??

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

    APR_REQUEST_OPERATION_CODE: int = 1
    APR_REPLY_OPERATION_CODE: int = 2

    # TODO : Check size of types in Python
    # FIXME: 'sender_ip' in 'bytes' ... should we change type to INT ??

    # FIXME: Replace call 'binascii.unhexlify('00:00:00:00:00:00')'
    # FIXME: Replace call 'socket.inet_aton("0.0.0.0")'

    # TODO: Move 'ETH_P_ARP ...' to ENUM ??

    def __init__(self) -> None:
        # TODO: handle default in the different way?
        self.htype: int = 1  # Hardware type (16 bits): 1 for ethernet
        self.ptype: int = ETH_P_IP  # Internet Protocol packet
        self.hlen: int = 6  # Hardware address length (8 bits): 6 bytes for MAC address
        self.plen: int = 4  # Protocol address length (8 bits): 4 bytes for IPv4 address
        self.opcode: int = 1  # 1=request / 2=reply

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

    # TODO: Check for performance [find and use fastest implementation]
    @staticmethod
    def str_2_ip(ip_address: str) -> bytes:
        return socket.inet_aton(ip_address)

    # TODO: Check for performance [find and use fastest implementation]
    @staticmethod
    def str_2_mac(mac_address: str) -> bytes:
        return binascii.unhexlify(mac_address.replace(':', ''))

    # TODO: Check for performance [find and use fastest implementation]
    # TODO: Implementation requires 'import six' .. it should not be here
    @staticmethod
    def mac_2_str(mac: bytes) -> str:
        return ':'.join('%02x' % i for i in six.iterbytes(mac))

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

    def is_request(self) -> bool:
        return ARPHeader.APR_REQUEST_OPERATION_CODE == self.opcode

    # TODO: implement __repr__() ??

    '''
    @property
    def protocol(self) -> int:
        return socket.ntohs(self.prototype)
    '''
