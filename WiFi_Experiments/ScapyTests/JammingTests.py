
import random
import struct
from datetime import datetime
from typing import List

from scapy.config import conf
from scapy.layers.dot11 import RadioTap, Dot11
from scapy.packet import Raw
from scapy.sendrecv import sendp

MAX_DATA_SIZE: int = 1526
INTERFACE_NAME: str = 'mon0'


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


if __name__ == "__main__":
    random_buffer: List = [random.randint(-128, 127) for _ in range(MAX_DATA_SIZE)]
    config: JamSetting = JamSetting(channel=7, power=48, period=1, length=128)
    # print(config)

    radio = RadioTap(len=18, present='Flags+Rate+Channel+dBm_AntSignal+Antenna')
    radio.Rate = 2
    radio.Channel = config.channel
    radio.dBm_AntSignal = -1 * int(config.power)

    hdr = Dot11(addr1="ff:ff:ff:ff:ff:ff", addr2="01:01:01:01:01:01", addr3="aa:aa:aa:bb:bb:bb")
    buffer = struct.pack('%sb' % config.length, *(random_buffer[0: config.length]))
    pl = Raw(load=buffer)

    doty = hdr / pl
    pkt = radio / doty
    packet = pkt.build()

    # socket = conf.L2socket(iface=INTERFACE_NAME)
    # socket.send(packet)

    sendp(pkt, iface=INTERFACE_NAME, count=int(1), inter=0.0)