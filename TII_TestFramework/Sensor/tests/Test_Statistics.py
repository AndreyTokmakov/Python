
import os
import sys  # TODO: Remove it
sys.path.insert(0, os.path.dirname(os.path.realpath(__file__)) + "/..")

from network.statistics.NetworkStats import NetworkStats


def minus_test():
    stat1: NetworkStats = NetworkStats()
    stat1.packets_total = 10
    stat1.icmp_packets = 20
    stat1.tcp_packets = 30
    stat1.udp_packets = 40

    stat2: NetworkStats = NetworkStats()
    stat2.packets_total = 1
    stat2.icmp_packets = 2
    stat2.tcp_packets = 3
    stat2.udp_packets = 4

    print(stat1 - stat2)
    print(stat1 + stat2)


if __name__ == '__main__':
    minus_test()