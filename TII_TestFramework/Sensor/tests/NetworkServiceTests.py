import os
import sys  # TODO: Remove it
sys.path.insert(0, os.path.dirname(os.path.realpath(__file__)) + "/..")

import time
import threading
import socket

from modules.Service import IService, ServicesPool
from network.Headers.EthernetHeader import EthernetHeader
from network.Headers.IPHeader import IPHeader
from network.Headers.TCPHeader import TCPHeader
from network.statistics.NetworkStats import NetworkStats

from database.model.NetworkGeneral import NetworkGeneral
from database.Database import Database

from sqlalchemy.orm import Session

ETHERNET_HEADER_LEN: int = 14
TCP_HEADER_LEN: int = 20


class NetworkMonitor(IService):
    ETHERNET_HEADER_LEN: int = 14

    def __init__(self) -> None:
        IService.__init__(self)
        self.stats: NetworkStats = NetworkStats()
        self.stats_dumber: threading.Thread = threading.Thread(target=self.stats_dump,
                                                               args=())
        self.db: Database = Database()

    def handler(self) -> bool:
        self.stats_dumber.start()  # TODO: wait
        self.sniff_traffic()
        return True

    # Have to use 'curr_stats' as immediate stats state copy
    def stats_dump(self) -> None:
        curr_stats, prev_stats, delta = self.stats.clone(), NetworkStats(), NetworkStats()
        while True:
            curr_stats = self.stats.clone()
            delta = curr_stats - prev_stats

            # os.system("clear")
            print(curr_stats, "\n", delta)

            prev_stats = curr_stats

            '''
            with Session(bind=self.db.engine) as session:
                # TODO: Add NetworkStats --> NetworkGeneral cast
                stat1 = NetworkGeneral(total=delta.packets_total,
                                       tcp=delta.packets_total,
                                       icmp=delta.icmp_packets,
                                       udp=delta.udp_packets)
                session.add_all([stat1])
                session.commit()
            '''

            time.sleep(5)

    def sniff_traffic(self) -> None:
        # create an INET, raw socket
        sock: socket = socket.socket(socket.AF_PACKET, socket.SOCK_RAW, socket.ntohs(0x0003))
        # TODO: check socket

        # receive a packet
        while True:
            recv = sock.recvfrom(65565)
            packet: bytes = recv[0]
            self.inspect_ethernet_packet(packet)

    def inspect_ethernet_packet(self, packet: bytes) -> None:
        ethernet_header: EthernetHeader = EthernetHeader(packet[: ETHERNET_HEADER_LEN])

        # Parse IP packets, IP Protocol number = 8
        if ethernet_header.protocol == 8:
            ip_data: bytes = packet[ETHERNET_HEADER_LEN: 20 + ETHERNET_HEADER_LEN]
            ip_header: IPHeader = IPHeader(ip_data)

            self.stats.packets_total += 1

            if socket.IPPROTO_ICMP == ip_header.protocol:
                self.stats.icmp_packets += 1
            elif socket.IPPROTO_TCP == ip_header.protocol:
                self.stats.tcp_packets += 1
            elif socket.IPPROTO_UDP == ip_header.protocol:
                self.stats.tcp_packets += 1


if __name__ == '__main__':
    service1 = NetworkMonitor()
    srv: IService = service1.start()
    srv.wait()
