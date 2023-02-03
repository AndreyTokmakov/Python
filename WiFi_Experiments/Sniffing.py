from scapy.all import *
from scapy.layers.dot11 import Dot11Beacon

interface_name: str = "wlp4s0"


def handle_packet(pkt):
    print(pkt.summary())


def find_beacons(pkt):
    # print(pkt.summary())
    if pkt.haslayer(Dot11Beacon):
        print("**** BECKON **** ")


def start_sniffing():
    # sniff(iface=interface_name, prn=handle_packet)
    sniff(iface=interface_name, prn=find_beacons)


if __name__ == '__main__':
    start_sniffing()

