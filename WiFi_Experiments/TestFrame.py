from scapy.layers.dot11 import RadioTap, Dot11, Dot11ProbeReq, Dot11Elt
from scapy.sendrecv import srp1


# https://research.securitum.com/generating-wifi-communication-in-scapy-tool/

if __name__ == "__main__":
    recipients_mac_address = 'ff:ff:ff:ff:ff:ff'
    your_mac_address = 'F4:8C:EB:17:6C:AA'
    ssid = 'Sc45y + W1F1'
    channel = chr(11)
    interface = 'wlp4s0'

    frame = RadioTap() \
            / Dot11(type=0, subtype=4, addr1=recipients_mac_address, addr2=your_mac_address, addr3=recipients_mac_address) \
            / Dot11ProbeReq() \
            / Dot11Elt(ID='SSID', info=ssid) \
            / Dot11Elt(ID='Rates', info='\x82\x84\x8b\x96\x0c\x12\x18') \
            / Dot11Elt(ID='ESRates', info='\x30\x48\x60\x6c') \
            / Dot11Elt(ID='DSset', info=channel)
    answer = srp1(frame, iface=interface)
    answer.show()
