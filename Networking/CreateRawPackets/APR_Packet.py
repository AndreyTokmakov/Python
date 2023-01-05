from __future__ import annotations

import binascii
import ipaddress
import os
import socket
import struct
from typing import List, Tuple, Any

import sys  # TODO: Remove it
sys.path.insert(0, os.path.dirname(os.path.realpath(__file__)) + "/../..")

from Networking.Headers.EthernetHeader import EthernetHeader
from Networking.CreateRawPackets.ARPHeader import ETH_P_IP, ETH_P_ARP, ARPHeader
from Networking.CreateRawPackets.IPUtils import IPUtils


ETHERNET_HEADER_LEN: int = 14
TCP_HEADER_LEN: int = 20


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
    src_mac, dst_mac = 'a8:93:4a:4e:00:6b', 'ff:ff:ff:ff:ff:ff'
    source_ip = "192.168.0.184"  # sender ip address: OUR interface IP address
    dest_ip_start: int = IPUtils.IP2Int_2("192.168.0.0")

    sock = create_raw_socket()
    sock.bind(("wlp4s0", 0))

    eth_hdr: EthernetHeader = EthernetHeader().set_destination_mac(dst_mac) \
        .set_source_mac(src_mac).set_protocol(ETH_P_ARP)

    arp_hdr = ARPHeader()
    arp_hdr.set_sender_ip(source_ip)
    arp_hdr.set_sender_mac(src_mac)

    for i in range(10):
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

    # apr_scan()

    # apr_header_fields_test()

    utils_test()
