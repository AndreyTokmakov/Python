from enum import IntEnum


class EthernetProtocolIDs(IntEnum):
    ETH_P_LOOP = 0x0060  # Ethernet Loopback packet
    ETH_P_PUP = 0x0200  # Xerox PUP packet
    ETH_P_PUPAT = 0x0201  # Xerox PUP Addr Trans packet
    ETH_P_TSN = 0x22F0  # TSN (IEEE 1722) packet
    ETH_P_ERSPAN2 = 0x22EB  # ERSPAN version 2 (type III)
    ETH_P_IP = 0x0800  # Internet Protocol packet
    ETH_P_X25 = 0x0805  # CCITT X.25
    ETH_P_ARP = 0x0806  # Address Resolution packet
    ETH_P_BPQ = 0x08FF  # G8BPQ AX.25 Ethernet Packet	[ NOT AN OFFICIALLY REGISTERED ID ]
    ETH_P_IEEEPUP = 0x0a00  # Xerox IEEE802.3 PUP packet
    ETH_P_IEEEPUPAT = 0x0a01  # Xerox IEEE802.3 PUP Addr Trans packet
    ETH_P_BATMAN = 0x4305  # B.A.T.M.A.N.-Advanced packet [ NOT AN OFFICIALLY REGISTERED ID ]
    ETH_P_DEC = 0x6000  # DEC Assigned proto
    ETH_P_DNA_DL = 0x6001  # DEC DNA Dump/Load
    ETH_P_DNA_RC = 0x6002  # DEC DNA Remote Console
    ETH_P_DNA_RT = 0x6003  # DEC DNA Routing
    ETH_P_LAT = 0x6004  # DEC LAT
    ETH_P_DIAG = 0x6005  # DEC Diagnostics
    ETH_P_CUST = 0x6006  # DEC Customer use
    ETH_P_SCA = 0x6007  # DEC Systems Comms Arch
    ETH_P_TEB = 0x6558  # Trans Ether Bridging
    ETH_P_RARP = 0x8035  # Reverse Addr Res packet
    ETH_P_ATALK = 0x809B  # Appletalk DDP
    ETH_P_AARP = 0x80F3  # Appletalk AARP
    ETH_P_8021Q = 0x8100  # 802.1Q VLAN Extended Header
    ETH_P_ERSPAN = 0x88BE  # ERSPAN type II
    ETH_P_IPX = 0x8137  # IPX over DIX
    ETH_P_IPV6 = 0x86DD  # IPv6 over bluebook
    ETH_P_PAUSE = 0x8808  # IEEE Pause frames. See 802.3 31B
    ETH_P_SLOW = 0x8809  # Slow Protocol. See 802.3ad 43B
    ETH_P_WCCP = 0x883E  # Web-cache coordination protocol
