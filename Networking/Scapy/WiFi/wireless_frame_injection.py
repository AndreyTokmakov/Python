from scapy.layers.dot11 import RadioTap, Dot11Deauth, Dot11, Dot11Beacon, Dot11Elt
from scapy.sendrecv import sendp
from scapy.volatile import RandString, RandNum


interface_name: str = 'wlp4s0'


if __name__ == "__main__":
    pkt = RadioTap() / \
          Dot11(addr1="ff:ff:ff:ff:ff:ff", addr2="01:01:01:01:01:01", addr3="00:01:02:03:04:05") / \
          Dot11Beacon(cap="ESS", timestamp=1) / \
          Dot11Elt(ID="SSID", info=RandString(RandNum(1, 50))) / \
          Dot11Elt(ID="Rates", info='\x82\x84\x0b\x16') / \
          Dot11Elt(ID="DSset", info="\x03") / \
          Dot11Elt(ID="TIM", info="\x00\x01\x00\x00")

    # sendp(pkt, iface=interface_name, loop=1)
    sendp(pkt, iface=interface_name)

    '''    
    for _ in range(10):
        sendp(pkt, iface="mon0")

    '''