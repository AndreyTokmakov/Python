from __future__ import annotations

import os
import socket
import struct

import sys  # TODO: Remove it
import time
from threading import Thread
from typing import Tuple

import six

sys.path.insert(0, os.path.dirname(os.path.realpath(__file__)) + "/../..")

from Networking.Headers.EthernetHeader import EthernetHeader
from Networking.CreateRawPackets.ARPHeader import ETH_P_IP, ETH_P_ARP, ARPHeader
from Networking.CreateRawPackets.IPUtils import IPUtils

ETHERNET_HEADER_LEN: int = 14
TCP_HEADER_LEN: int = 20
BROADCAST_MAC: str = 'ff:ff:ff:ff:ff:ff'

# TODO: Need to get them automatically:

INTERFACE_NAME: str = 'wlp4s0'
INTERFACE_MAC_ADDR: str = 'a8:93:4a:4e:00:6b'
INTERFACE_IP_ADDR: str = '192.168.0.184'


def mac_bytes_2_str(mac: bytes) -> str:
    return ':'.join('%02x' % i for i in six.iterbytes(mac))


def create_raw_socket() -> socket:
    # create an INET, raw socket
    try:
        sock: socket = socket.socket(socket.AF_PACKET, socket.SOCK_RAW, socket.ntohs(0x0003))
        return sock
    except socket.error as error:
        print(f'Socket could not be created. Error: {error}')
        sys.exit()


def apr_scan():
    src_mac = INTERFACE_MAC_ADDR
    source_ip = INTERFACE_IP_ADDR  # sender ip address: OUR interface IP address
    dest_ip_start: int = IPUtils.IP2Int_2("192.168.0.0")

    sock = create_raw_socket()
    sock.bind((INTERFACE_NAME, 0))

    eth_hdr: EthernetHeader = EthernetHeader().set_destination_mac(BROADCAST_MAC) \
        .set_source_mac(src_mac).set_protocol(ETH_P_ARP)  # TODO: ETH_P_ARP --> Enum

    arp_hdr = ARPHeader()
    arp_hdr.set_sender_ip(source_ip)
    arp_hdr.set_sender_mac(src_mac)

    for i in range(10):
        target_id: str = IPUtils.Int2IP(dest_ip_start + i)
        arp_hdr.set_target_ip(target_id)
        packet: bytes = eth_hdr.data + arp_hdr.data
        sock.send(packet)


def sniff_arp_packets():
    sock = create_raw_socket()
    sock.bind((INTERFACE_NAME, 0))

    ARP_TYPE: int = socket.ntohs(ETH_P_ARP)  # TODO: To consts?
    while True:
        recv = sock.recvfrom(65565)
        packet: bytes = recv[0]
        ethernet_header: EthernetHeader = EthernetHeader.create(packet[: ETHERNET_HEADER_LEN])

        if ethernet_header.protocol == ARP_TYPE:
            arp: ARPHeader = ARPHeader.create(packet[ETHERNET_HEADER_LEN: 28 + ETHERNET_HEADER_LEN])

            target_ip: str = socket.inet_ntoa(struct.pack('4s', arp.target_ip))
            sender_ip: str = socket.inet_ntoa(struct.pack('4s', arp.sender_ip))

            # target_mac: bytes = struct.pack('6s', arp.target_mac)
            # target_mac_str: str = mac_bytes_2_str(target_mac)

            sender_mac: bytes = struct.pack('6s', arp.sender_mac)
            sender_mac_str: str = mac_bytes_2_str(sender_mac)

            if arp.is_request():
                print(f"Request: who-has {target_ip} tell {sender_ip}")
            else:
                print(f"Reply: {sender_ip} is-at {sender_mac_str}")

            # packet = memoryview(recv[0])
            # inspect_ip_packet(packet)


def wait_for_apr_reply():
    sock = create_raw_socket()
    sock.bind((INTERFACE_NAME, 0))

    # mac: str = 'a8:93:4a:4e:00:6b'
    mac: str = 'f4:8c:eb:00:b8:61'
    mac_to_wait_for: bytes = ARPHeader.str_2_mac(mac)

    ARP_TYPE: int = socket.ntohs(ETH_P_ARP)  # TODO: To consts?
    while True:
        recv: Tuple = sock.recvfrom(65565)
        packet: bytes = recv[0]
        ethernet_header: EthernetHeader = EthernetHeader.create(packet[: ETHERNET_HEADER_LEN])

        if ethernet_header.protocol == ARP_TYPE:
            arp: ARPHeader = ARPHeader.create(packet[ETHERNET_HEADER_LEN: 28 + ETHERNET_HEADER_LEN])

            # target_ip: str = socket.inet_ntoa(struct.pack('4s', arp.target_ip))
            # target_mac_str: str = mac_bytes_2_str(arp.target_mac)
            sender_ip: str = socket.inet_ntoa(struct.pack('4s', arp.sender_ip))
            sender_mac_str: str = mac_bytes_2_str(arp.sender_mac)

            if not arp.is_request() and arp.sender_mac == mac_to_wait_for:
                print(f"Reply: {sender_ip} is-at {sender_mac_str}")
                return


def send_request_and_wait_for_response():
    thread = Thread(target=wait_for_apr_reply)
    thread.start()

    time.sleep(0.1)

    print("Scanning....")
    apr_scan()


if __name__ == '__main__':
    # apr_scan()
    # sniff_arp_packets()
    # wait_for_apr_reply()

    send_request_and_wait_for_response()

    pass
