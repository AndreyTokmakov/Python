import warnings
from cryptography.utils import CryptographyDeprecationWarning

from scapy.all import *
from collections import namedtuple
import csv
import sys
import time

from scapy.layers.dot11 import RadioTap, Dot11

JamSetting = namedtuple("JamSetting", "timestamp channel power period length")


def namedtuple_test():
    settings1 = JamSetting(timestamp=datetime.now(), channel=1, power=24, period=1, length=2)
    print(settings1)


def get_ip_address():
    ipaddr = None
    while ipaddr is None:
        try:
            s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            s.connect(("8.8.8.8", 80))
            ipaddr = s.getsockname()[0]
        except:
            pass
    return ipaddr


def radioTap_test():
    radio = RadioTap(len=18, present='Flags+Rate+Channel+dBm_AntSignal+Antenna')
    radio.Rate = 2
    radio.Channel = 1
    # rt.dBm_TX_Power=int(js.power)
    radio.dBm_AntSignal = 28.0  #  -1*int(js.power)

    hdr = Dot11(addr1='ff:ff:ff:ff:ff:ff', addr2='00:11:22:33:44:55', addr3='00:11:22:33:44:55')

    print(hdr)
    print(radio)


if __name__ == '__main__':
    # print(get_ip_address())

    radioTap_test()

    pass

'''
 IEEE 802.11 Radiotap Capture header (radiotap)
       radiotap.antenna  Antenna
           Unsigned 32-bit integer
           Antenna number this frame was sent/received over (starting at 0)

       radiotap.channel  Channel
           Unsigned 32-bit integer
           802.11 channel number that this frame was sent/received on

       radiotap.channel.freq  Channel frequency
           Unsigned 32-bit integer
           Channel frequency in megahertz that this frame was sent/received on

       radiotap.channel.type  Channel type
           Unsigned 16-bit integer
           Channel type

       radiotap.channel.type.2ghz  2 GHz spectrum
           Boolean
           Channel Type 2 GHz spectrum

       radiotap.channel.type.5ghz  5 GHz spectrum
           Boolean
           Channel Type 5 GHz spectrum

       radiotap.channel.type.cck  Complementary Code Keying (CCK)
           Boolean
           Channel Type Complementary Code Keying (CCK) Modulation

       radiotap.channel.type.dynamic  Dynamic CCK-OFDM
           Boolean
           Channel Type Dynamic CCK-OFDM Channel

       radiotap.channel.type.gfsk  Gaussian Frequency Shift Keying (GFSK)
           Boolean
           Channel Type Gaussian Frequency Shift Keying (GFSK) Modulation

       radiotap.channel.type.gsm  GSM (900MHz)
           Boolean
           Channel Type GSM

       radiotap.channel.type.half  Half Rate Channel (10MHz Channel Width)
           Boolean
           Channel Type Half Rate

       radiotap.channel.type.ofdm  Orthogonal Frequency-Division Multiplexing (OFDM)
           Boolean
           Channel Type Orthogonal Frequency-Division Multiplexing (OFDM)

       radiotap.channel.type.passive  Passive
           Boolean
           Channel Type Passive

       radiotap.channel.type.quarter  Quarter Rate Channel (5MHz Channel Width)
           Boolean
           Channel Type Quarter Rate

       radiotap.channel.type.sturbo  Static Turbo
           Boolean
           Channel Type Status Turbo

       radiotap.channel.type.turbo  Turbo
           Boolean
           Channel Type Turbo

       radiotap.channel.xtype.passive  Passive
           Boolean
           Channel Type Passive

       radiotap.datarate  Data rate
           Unsigned 32-bit integer
           Speed this frame was sent/received at

       radiotap.db_antnoise  SSI Noise (dB)
           Unsigned 32-bit integer
           RF noise power at the antenna from a fixed, arbitrary value in decibels

       radiotap.db_antsignal  SSI Signal (dB)
           Unsigned 32-bit integer
           RF signal power at the antenna from a fixed, arbitrary value in decibels

       radiotap.db_txattenuation  Transmit attenuation (dB)
           Unsigned 16-bit integer
           Transmit power expressed as decibels from max power set at factory (0 is max power)

       radiotap.dbm_antsignal  SSI Signal (dBm)
           Signed 32-bit integer
           RF signal power at the antenna from a fixed, arbitrary value in decibels from one milliwatt

       radiotap.fcs  802.11 FCS
           Unsigned 32-bit integer
           Frame check sequence of this frame

       radiotap.fcs_bad  Bad FCS
           Boolean
           Specifies if this frame has a bad frame check sequence

       radiotap.fhss.hopset  FHSS Hop Set
           Unsigned 8-bit integer
           Frequency Hopping Spread Spectrum hopset

       radiotap.fhss.pattern  FHSS Pattern
           Unsigned 8-bit integer
           Frequency Hopping Spread Spectrum hop pattern

       radiotap.flags  Flags
           Unsigned 8-bit integer

       radiotap.flags.badfcs  Bad FCS
           Boolean
           Frame received with bad FCS

       radiotap.flags.cfp  CFP
           Boolean
           Sent/Received during CFP

       radiotap.flags.datapad  Data Pad
           Boolean
           Frame has padding between 802.11 header and payload

       radiotap.flags.fcs  FCS at end
           Boolean
           Frame includes FCS at end

       radiotap.flags.frag  Fragmentation
           Boolean
           Sent/Received with fragmentation

       radiotap.flags.preamble  Preamble
           Boolean
           Sent/Received with short preamble

       radiotap.flags.shortgi  Short GI
           Boolean
           Frame Sent/Received with HT short Guard Interval

       radiotap.flags.wep  WEP
           Boolean
           Sent/Received with WEP encryption

       radiotap.length  Header length
           Unsigned 16-bit integer
           Length of header including version, pad, length and data fields

       radiotap.mactime  MAC timestamp
           Unsigned 64-bit integer
            Value in microseconds of the MAC's Time Synchronization Function timer when the first bit of the MPDU arrived at the MAC.

       radiotap.pad  Header pad
           Unsigned 8-bit integer
           Padding

       radiotap.present  Present flags
           Unsigned 32-bit integer
           Bitmask indicating which fields are present

       radiotap.present.antenna  Antenna
           Boolean
           Specifies if the antenna number field is present

       radiotap.present.channel  Channel
           Boolean
           Specifies if the transmit/receive frequency field is present

       radiotap.present.db_antnoise  DB Antenna Noise
           Boolean
           Specifies if the RF signal power at antenna in dBm field is present

       radiotap.present.db_antsignal  DB Antenna Signal
           Boolean
           Specifies if the RF signal power at antenna in dB field is present

       radiotap.present.db_tx_attenuation  DB TX Attenuation
           Boolean
           Specifies if the transmit power from max power (in dB) field is present

       radiotap.present.dbm_antnoise  DBM Antenna Noise
           Boolean
           Specifies if the RF noise power at antenna field is present

       radiotap.present.dbm_antsignal  DBM Antenna Signal
           Boolean
           Specifies if the antenna signal strength in dBm is present

       radiotap.present.dbm_tx_attenuation  DBM TX Attenuation
           Boolean
           Specifies if the transmit power from max power (in dBm) field is present

       radiotap.present.ext  Ext
           Boolean
           Specifies if there are any extensions to the header present

       radiotap.present.fcs  FCS in header
           Boolean
           Specifies if the FCS field is present

       radiotap.present.fhss  FHSS
           Boolean
           Specifies if the hop set and pattern is present for frequency hopping radios

       radiotap.present.flags  Flags
           Boolean
           Specifies if the channel flags field is present

       radiotap.present.lock_quality  Lock Quality
           Boolean
           Specifies if the signal quality field is present

       radiotap.present.rate  Rate
           Boolean
           Specifies if the transmit/receive rate field is present

       radiotap.present.rxflags  RX flags
           Boolean
           Specifies if the RX flags field is present

       radiotap.present.tsft  TSFT
           Boolean
           Specifies if the Time Synchronization Function Timer field is present

       radiotap.present.tx_attenuation  TX Attenuation
           Boolean
           Specifies if the transmit power from max power field is present

       radiotap.present.xchannel  Channel+
           Boolean
           Specifies if the extended channel info field is present

       radiotap.quality  Signal Quality
           Unsigned 16-bit integer
           Signal quality (unitless measure)

       radiotap.rxflags  RX flags
           Unsigned 16-bit integer

       radiotap.rxflags.badplcp  Bad PLCP
           Boolean
           Frame with bad PLCP

       radiotap.txattenuation  Transmit attenuation
           Unsigned 16-bit integer
           Transmit power expressed as unitless distance from max power set at factory (0 is max power)

       radiotap.txpower  Transmit power
           Signed 32-bit integer
           Transmit power in decibels per one milliwatt (dBm)

       radiotap.version  Header revision
           Unsigned 8-bit integer
           Version of radiotap header format

       radiotap.xchannel  Channel number
           Unsigned 32-bit integer

       radiotap.xchannel.flags  Channel type
           Unsigned 32-bit integer

       radiotap.xchannel.freq  Channel frequency
           Unsigned 32-bit integer

       radiotap.xchannel.type.2ghz  2 GHz spectrum
           Boolean
           Channel Type 2 GHz spectrum

       radiotap.xchannel.type.5ghz  5 GHz spectrum
           Boolean
           Channel Type 5 GHz spectrum

       radiotap.xchannel.type.cck  Complementary Code Keying (CCK)
           Boolean
           Channel Type Complementary Code Keying (CCK) Modulation

       radiotap.xchannel.type.dynamic  Dynamic CCK-OFDM
           Boolean
           Channel Type Dynamic CCK-OFDM Channel

       radiotap.xchannel.type.gfsk  Gaussian Frequency Shift Keying (GFSK)
           Boolean
           Channel Type Gaussian Frequency Shift Keying (GFSK) Modulation

       radiotap.xchannel.type.gsm  GSM (900MHz)
           Boolean
           Channel Type GSM

       radiotap.xchannel.type.half  Half Rate Channel (10MHz Channel Width)
           Boolean
           Channel Type Half Rate

       radiotap.xchannel.type.ht20  HT Channel (20MHz Channel Width)
           Boolean
           Channel Type HT/20

       radiotap.xchannel.type.ht40d  HT Channel (40MHz Channel Width with Extension channel below)
           Boolean
           Channel Type HT/40-

       radiotap.xchannel.type.ht40u  HT Channel (40MHz Channel Width with Extension channel above)
           Boolean
           Channel Type HT/40+

       radiotap.xchannel.type.ofdm  Orthogonal Frequency-Division Multiplexing (OFDM)
           Boolean
           Channel Type Orthogonal Frequency-Division Multiplexing (OFDM)

       radiotap.xchannel.type.quarter  Quarter Rate Channel (5MHz Channel Width)
           Boolean
           Channel Type Quarter Rate

       radiotap.xchannel.type.sturbo  Static Turbo
           Boolean
           Channel Type Status Turbo

       radiotap.xchannel.type.turbo  Turbo
           Boolean
           Channel Type Turbo
'''
