from telnetlib import IP

from scapy.all import *
from scapy.layers.inet import ICMP
from scapy.layers.l2 import Ether


def build_ethernet_packet():
    packet = Ether()
    packet.show()

    print(f'Packet (HEX)     : {hexdump(packet)}')
    print(f'packet.type      : {packet.type}')
    print(f'packet.type (HEX): {hex(packet.type)}')


def ip_packet():
    pkt = Ether() / IP(dst='8.8.8.8')
    pkt.show()


def send_icmp():
    pkt = IP(dst='8.8.8.8') / ICMP()
    response = sr1(pkt)
    print(response)

    # 12:14:27.302110 IP 192.168.0.184 > 8.8.8.8: ICMP echo request, id 0, seq 0, length 8
    # 12:14:27.311004 IP 8.8.8.8 > 192.168.0.184: ICMP echo reply, id 0, seq 0, length 8


if __name__ == '__main__':
    # build_ethernet_packet()
    # ip_packet()
    send_icmp()

