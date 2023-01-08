

import warnings
from cryptography.utils import CryptographyDeprecationWarning
from scapy.layers.dot11 import RadioTap, Dot11Deauth, Dot11

with warnings.catch_warnings():
    warnings.filterwarnings('ignore', category=CryptographyDeprecationWarning)
    # FIXME: ignoring warnings from cryptography.
    from scapy.all import *


ap_list = []


def PacketHandler(packet):
    if packet.haslayer(Dot11):
        if packet.type == 0 and packet.subtype == 8:
            if packet.addr2 not in ap_list:
                ap_list.append(packet.addr2)
                print("Access Point MAC: %s with SSID: %s " % (packet.addr2, packet.info))


if __name__ == '__main__':
    sniff(iface="wlp4s0", prn=PacketHandler)
