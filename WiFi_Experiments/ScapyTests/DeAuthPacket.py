from scapy.layers.dot11 import RadioTap, Dot11Deauth, Dot11

if __name__ == "__main__":
    # A deauth packet appears in the air
    packet = (RadioTap() / Dot11(type=0, subtype=12,
                                 addr1="00:00:00:00:00:00",  # client mac
                                 addr2="00:00:00:00:00:00",  # access_point_mac
                                 addr3="00:00:00:00:00:00"  # access_point_mac
                                 ) / Dot11Deauth(reason=7))

    print(packet)
