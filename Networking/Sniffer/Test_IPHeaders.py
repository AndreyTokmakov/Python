
import socket
import struct

from Headers.IpHeader import IpHeader
from Headers.IPHeader import IPHeader

import sys
sys.path.append('/home/andtokm/DiskS/ProjectsUbuntu/Python/Networking/Sniffer')

ETHERNET_HEADER_LEN: int = 14


def inspect_ethernet_packet(packet: bytes) -> None:
    eth_header: bytes = packet[: ETHERNET_HEADER_LEN]
    eth = struct.unpack('!6s6sH', eth_header)
    eth_protocol: int = socket.ntohs(eth[2])
    stc_mac, dst_mac = eth_header[0:6], packet[6:12]

    # Parse IP packets, IP Protocol number = 8
    if eth_protocol == 8:
        ip_data: bytes = packet[ETHERNET_HEADER_LEN: 20 + ETHERNET_HEADER_LEN]

        ip_header_old = IpHeader()
        ip_header_old.decode(ip_data)

        ip_header = IPHeader(ip_data)

        ip_header_decoded = IPHeader(ip_data)
        ip_header_decoded.decode(ip_data)

        if ip_header_old.tos != ip_header.tos:
            print(f"Wrong tos: {ip_header_old.tos} != {ip_header.tos:}")
        if ip_header_old.totalLen != ip_header.totalLen:
            print(f"Wrong totalLen: {ip_header_old.totalLen} != {ip_header.totalLen:}")
        if ip_header_old.identification != ip_header.id:
            print(f"Wrong id: {ip_header_old.identification} != {ip_header.id:}")
        if ip_header_old.fragment != ip_header.offset:
            print(f"Wrong offset: {ip_header_old.fragment} != {ip_header.offset:}")
        if ip_header_old.checksum != ip_header.checksum:
            print(f"Wrong checksum: {ip_header_old.checksum} != {ip_header.checksum:}")
        if ip_header_old.ttl != ip_header.ttl:
            print("Wrong TTL")
        if ip_header_old.protocol != ip_header.protocol:
            print(f"Wrong protocol: {ip_header_old.protocol} != {ip_header.protocol:}")

        if ip_header.ver != ip_header_decoded.ver:
            print(f"VER protocol: {ip_header.ver} != {ip_header_decoded.ver:}")
        if ip_header.ihl != ip_header_decoded.ihl:
            print(f"ihl protocol: {ip_header.ihl} != {ip_header_decoded.ihl:}")

        # print(ip_header2.ver)
        # print(ip_header2.ihl)
        # print(ip_header2.totalLen)
        # print(ip_header.IntToIP(ip_header.srcIP), ip_header2.sourceIpAsStr, ip_header3.sourceIpAsStr)


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
