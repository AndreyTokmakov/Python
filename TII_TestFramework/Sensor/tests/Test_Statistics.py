import os
import sys  # TODO: Remove it

from TII_TestFramework.Sensor.statistics.NetworkStats import NetworkStats

sys.path.insert(0, os.path.dirname(os.path.realpath(__file__)) + "/..")


class NetworkStatsTests(object):

    @staticmethod
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

    @staticmethod
    def serialize():
        stats: NetworkStats = NetworkStats()
        stats.packets_total = 10
        stats.icmp_packets = 20
        stats.tcp_packets = 30
        stats.udp_packets = 40

        print(stats)


if __name__ == '__main__':
    # NetworkStatsTests.minus_test()
    NetworkStatsTests.serialize()

