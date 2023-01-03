from __future__ import annotations

import binascii
import os
# import module
import socket
import struct
import sys
from typing import List, Tuple, Any

import sys  # TODO: Remove it

sys.path.insert(0, os.path.dirname(os.path.realpath(__file__)) + "/../..")

from Networking.Headers.EthernetHeader import EthernetHeader

ETHERNET_HEADER_LEN: int = 14
TCP_HEADER_LEN: int = 20

ETH_P_LOOP = 0x0060  # hernet Loopback packet
ETH_P_PUP = 0x0200  # rox PUP packet
ETH_P_PUPAT = 0x0201  # rox PUP Addr Trans packet
ETH_P_IP = 0x0800  # ternet Protocol packet
ETH_P_X25 = 0x0805  # ITT X.25
ETH_P_ARP = 0x0806  # dress Resolution packet
ETH_P_IEEEPUP = 0x0a00  # rox IEEE802.3 PUP packet
ETH_P_IEEEPUPAT = 0x0a01  # rox IEEE802.3 PUP Addr Trans packet
ETH_P_DEC = 0x6000  # C Assigned proto
ETH_P_DNA_DL = 0x6001  # C DNA Dump/Load
ETH_P_DNA_RC = 0x6002  # C DNA Remote Console
ETH_P_DNA_RT = 0x6003  # C DNA Routing
ETH_P_LAT = 0x6004  # C LAT
ETH_P_DIAG = 0x6005  # C Diagnostics
ETH_P_CUST = 0x6006  # C Customer use
ETH_P_SCA = 0x6007  # C Systems Comms Arch
ETH_P_TEB = 0x6558  # ans Ether Bridging
ETH_P_RARP = 0x8035  # verse Addr Res packet
ETH_P_ATALK = 0x809B  # pletalk DDP
ETH_P_AARP = 0x80F3  # pletalk AARP
ETH_P_8021Q = 0x8100  # 2.1Q VLAN Extended Header
ETH_P_IPX = 0x8137  # X over DIX
ETH_P_IPV6 = 0x86DD  # v6 over bluebook
ETH_P_PAUSE = 0x8808  # EE Pause frames. See 802.3 31B
ETH_P_SLOW = 0x8809  # ow Protocol. See 802.3ad 43B
ETH_P_WCCP = 0x883E  # b-cache coordination protocol

'''
    uint16_t htype {0};
    uint16_t ptype {0};
    uint8_t  hlen {};
    uint8_t  plen {};
    uint16_t opcode {0};
    uint8_t  sender_mac[6]{};
    uint32_t sender_ip {};
    uint8_t  target_mac[6]{};
    uint32_t target_ip {};

    htype = 1  # Hardware_type ethernet
    ptype = 0x0800  # Protocol type TCP
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


'''


class ARPHeader(object):
    ARP_HEADED_FORMAT: str = '!HHBBH6s4s6s4s'

    # TODO: Check size of types in Python
    def __init__(self) -> None:
        self.htype = 0
        self.ptype = 0
        self.hlen = 0
        self.plen = 0
        self.opcode = 0
        self.sender_mac: bytes = binascii.unhexlify('000000000000')
        self.sender_ip: bytes = socket.inet_aton("0.0.0.0")
        self.target_mac: bytes = binascii.unhexlify('000000000000')
        self.target_ip: bytes = socket.inet_aton("0.0.0.0")

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

    '''
    def set_source_mac(self, mac: str) -> EthernetHeader:
        self.source_mac = binascii.unhexlify(mac.replace(':', ''))
        return self

    def set_destination_mac(self, mac: str) -> EthernetHeader:
        self.destination_mac = binascii.unhexlify(mac.replace(':', ''))
        return self

    def set_protocol(self, protocol: int) -> EthernetHeader:
        self.prototype = protocol
        return self
    '''

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

    '''
    @property
    def protocol(self) -> int:
        return socket.ntohs(self.prototype)
    '''


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
        .set_source_mac(src_mac).set_protocol(0x0806)  # 0x0806 for ARP

    # ARP header
    htype = 1  # Hardware_type ethernet
    ptype = 0x0800  # Protocol type TCP
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
    src_mac, dst_mac = 'a8:93:4a:4e:00:6b', 'ff:ff:ff:ff:ff:ff'
    source_ip = "192.168.0.184"  # sender ip address
    dest_ip = "192.168.0.118"  # target ip address

    eth_header = EthernetHeader().set_destination_mac(dst_mac) \
        .set_source_mac(src_mac).set_protocol(0x0806)  # 0x0806 for ARP

    arp = ARPHeader()
    arp.htype = 1  # Hardware_type ethernet
    arp.ptype = 0x0800  # Protocol type TCP
    arp.hlen = 6  # Hardware address Len
    arp.plen = 4  # Protocol addr. len
    arp.opcode = 1  # 1=request / 2=reply
    arp.sender_ip = socket.inet_aton(source_ip)
    arp.sender_mac = eth_header.source_mac
    arp.target_ip = socket.inet_aton(dest_ip)

    packet = eth_header.data + arp.data

    sock = create_raw_socket()
    sock.bind(("wlp4s0", 0))

    for _ in range(5):
        sock.send(packet)


if __name__ == '__main__':
    # create_raw_socket()
    # ethernet_packet_test()
    # send_arp_packet_test()
    send_arp_packet_test_2()
