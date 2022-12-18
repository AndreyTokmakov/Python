import socket
import struct

from Headers.EthernetHeader import EthernetHeader
from Headers.IPHeader import IPHeader
from Headers.TCPHeader import TCPHeader

import sys

sys.path.append('/home/andtokm/DiskS/ProjectsUbuntu/Python/Networking/Sniffer')

ETHERNET_HEADER_LEN: int = 14
TCP_HEADER_LEN: int = 20


def inspect_ethernet_packet(packet: bytes) -> None:
    ethernet_header: EthernetHeader = EthernetHeader(packet[: ETHERNET_HEADER_LEN])

    # Parse IP packets, IP Protocol number = 8
    if ethernet_header.protocol == 8:
        ip_data: bytes = packet[ETHERNET_HEADER_LEN: 20 + ETHERNET_HEADER_LEN]
        ip_header: IPHeader = IPHeader(ip_data)

        # TCP protocol
        if 6 == ip_header.protocol:

            offset: int = ETHERNET_HEADER_LEN + ip_header.ipHeaderLength
            tcp_header_bytes: bytes = packet[offset: offset + TCP_HEADER_LEN]
            tcp_header: TCPHeader = TCPHeader(tcp_header_bytes)
            tcp_header.decode(tcp_header_bytes)

            '''
            print(f'{ip_header.sourceIpAsStr}:{tcp_header.source_port} --> '
                  f'{ip_header.destIpAsStr}:{tcp_header.dest_port}  '
                  f'win: {tcp_header.window} checksum: {tcp_header.checksum} '
                  f'seq: {tcp_header.sequence} ack: {tcp_header.acknowledgement} '
                  f'data offset: {tcp_header.dataOffset}')
            '''

            data_offset: int = ip_header.ipHeaderLength + tcp_header.dataOffset + ETHERNET_HEADER_LEN
            data_block_size = len(packet) - data_offset

            # print(f'data size: {data_block_size}')
            if 8080 == tcp_header.dest_port or 8080 == tcp_header.source_port:
                data: bytes = packet[data_offset:]
                print(data.decode('utf-8'))


def grab_traffic() -> None:
    # create an INET, raw socket
    sock: socket = socket.socket(socket.AF_PACKET, socket.SOCK_RAW, socket.ntohs(0x0003))

    # receive a packet
    while True:
        recv = sock.recvfrom(65565)
        # packet = memoryview(recv[0])
        packet = recv[0]
        inspect_ethernet_packet(packet)


if __name__ == '__main__':
    grab_traffic()
