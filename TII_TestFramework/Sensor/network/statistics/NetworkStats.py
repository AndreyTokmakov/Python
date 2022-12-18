from __future__ import annotations


class NetworkStats:

    def __init__(self):
        self.packets_total: int = 0
        self.icmp_packets: int = 0
        self.tcp_packets: int = 0
        self.udp_packets: int = 0

    # Overload (+) operator:
    def __add__(self, right: NetworkStats) -> NetworkStats:
        result: NetworkStats = NetworkStats()
        result.packets_total = self.packets_total + right.packets_total
        result.icmp_packets = self.icmp_packets + right.icmp_packets
        result.tcp_packets = self.tcp_packets + right.tcp_packets
        result.udp_packets = self.udp_packets + right.udp_packets
        return result

    # Overload (+=) operator:
    def __iadd__(self, right: NetworkStats) -> NetworkStats:
        return self + right

    # Overload (-) operator:
    def __sub__(self, right: NetworkStats) -> NetworkStats:
        result: NetworkStats = NetworkStats()
        result.packets_total = self.packets_total - right.packets_total
        result.icmp_packets = self.icmp_packets - right.icmp_packets
        result.tcp_packets = self.tcp_packets - right.tcp_packets
        result.udp_packets = self.udp_packets - right.udp_packets
        return result

    def clone(self) -> NetworkStats:
        copy: NetworkStats = NetworkStats()
        copy.packets_total = self.packets_total
        copy.icmp_packets = self.icmp_packets
        copy.tcp_packets = self.tcp_packets
        copy.udp_packets = self.udp_packets
        return copy

    # Overload (-=) operator:
    def __isub__(self, right: NetworkStats) -> NetworkStats:
        return self - right

    def __repr__(self):
        return 'NetworkStats [' \
               f'\n\tpackets_total: {self.packets_total}' \
               f'\n\ticmp_packets: {self.icmp_packets}' \
               f'\n\ttcp_packets: {self.tcp_packets}' \
               f'\n\tudp_packets: {self.udp_packets}' \
               '\n]'

