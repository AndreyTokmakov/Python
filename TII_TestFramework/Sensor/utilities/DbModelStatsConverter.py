import os
import sys

sys.path.insert(0, os.path.dirname(os.path.realpath(__file__)) + "/../statistics")  # REMOVE

from NetworkStats import NetworkStats
from database.model.NetworkGeneral import NetworkGeneral


class DbModelStatsConverter(object):

    @staticmethod
    def NetworkStats_To_NetworkGeneral(stats: NetworkStats) -> NetworkGeneral:
        return NetworkGeneral(timestamp=stats.timestamp,
                              total=stats.packets_total,
                              tcp=stats.tcp_packets,
                              icmp=stats.icmp_packets,
                              udp=stats.udp_packets)

    @staticmethod
    def NetworkGeneral_To_NetworkStats(model: NetworkStats) -> NetworkStats:
        stats: NetworkStats = NetworkStats()
        stats.timestamp = model.timestamp
        stats.packets_total = model.total
        stats.icmp_packets = model.icmp
        stats.tcp_packets = model.tcp
        stats.udp_packets = model.udp
        return stats
