from scapy.layers.dot11 import Dot11, Dot11ProbeResp, Dot11Beacon, Dot11Elt
from scapy.sendrecv import sniff

interface = 'wlp4s0'

known = {}


def callback(frame):
    # print("callback")
    if frame.haslayer(Dot11):
        print("has Dot11 layer")

        if frame.haslayer(Dot11Beacon) or frame.haslayer(Dot11ProbeResp):

            source = frame[Dot11].addr2
            if source not in known:
                ssid = frame[Dot11Elt][0].info
                channel = frame[Dot11Elt][2].info
                channel = int(channel.encode('hex'), 16)
                print(f"SSID: '{ssid}', BSSID: {source}, channel: {channel}")
                known[source] = True


if __name__ == "__main__":
    sniff(iface=interface, prn=callback)

