from __future__ import annotations

import binascii
import socket
import struct
from typing import Tuple, Any
import six

from Constants import EthernetProtocolIDs


class ARPHeader(object):
    ARP_HEADED_FORMAT: str = '!HHBBH6s4s6s4s'

    APR_REQUEST_OPERATION_CODE: int = 1
    APR_REPLY_OPERATION_CODE: int = 2

    # TODO : Check size of types in Python
    # FIXME: 'sender_ip' in 'bytes' ... should we change type to INT ??

    # FIXME: Replace call 'binascii.unhexlify('00:00:00:00:00:00')'
    # FIXME: Replace call 'socket.inet_aton("0.0.0.0")'

    def __init__(self) -> None:
        # TODO: handle default in the different way?
        self.htype: int = 1  # Hardware type (16 bits): 1 for ethernet
        self.ptype: int = EthernetProtocolIDs.ETH_P_IP  # Internet Protocol packet
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
