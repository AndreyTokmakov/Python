import os
import sys


sys.path.insert(0, os.path.dirname(os.path.realpath(__file__)) + "/../statistics")  # REMOVE

import time
import threading
import socket

from modules.Service import IService, ServicesPool
from network.Headers.EthernetHeader import EthernetHeader
from network.Headers.IPHeader import IPHeader
from network.Headers.TCPHeader import TCPHeader
from NetworkStats import NetworkStats

from database.model.NetworkGeneral import NetworkGeneral
from database.Database import Database

from utilities.DbModelStatsConverter import DbModelStatsConverter
from sqlalchemy.orm import Session

ETHERNET_HEADER_LEN: int = 14
TCP_HEADER_LEN: int = 20


class NetworkMonitor(IService):
    ETHERNET_HEADER_LEN: int = 14

    WRITE_STATS_TO_DB_TIMEOUT: float = 5.0

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

            # TODO: Add NetworkStats --> NetworkGeneral cast
            stats: NetworkGeneral = DbModelStatsConverter.NetworkStats_To_NetworkGeneral(delta)

            # TODO: here we may need to use lock
            with Session(bind=self.db.engine) as session:
                session.add_all([stats])
                session.commit()

            prev_stats = curr_stats
            time.sleep(NetworkMonitor.WRITE_STATS_TO_DB_TIMEOUT)

    def sniff_traffic(self) -> None:
        # create an INET, raw socket
        sock: socket = socket.socket(socket.AF_PACKET, socket.SOCK_RAW, socket.ntohs(0x0003))
        # TODO: check socket

        # receive a packet
        while True:
            # TODO: size --> to constants
            recv = sock.recvfrom(65565)
            packet: bytes = recv[0]
            self.inspect_ethernet_packet(packet)

    def inspect_ethernet_packet(self, packet: bytes) -> None:
        ethernet_header: EthernetHeader = EthernetHeader(packet[: ETHERNET_HEADER_LEN])

        # Parse IP packets, IP Protocol number = 8
        if ethernet_header.protocol == 8 and len(packet) > (ETHERNET_HEADER_LEN + 20):
            ip_data: bytes = packet[ETHERNET_HEADER_LEN: 20 + ETHERNET_HEADER_LEN]
            ip_header: IPHeader = IPHeader(ip_data)

            self.stats.packets_total += 1

            if socket.IPPROTO_ICMP == ip_header.protocol:
                self.stats.icmp_packets += 1
            elif socket.IPPROTO_TCP == ip_header.protocol:
                self.stats.tcp_packets += 1
            elif socket.IPPROTO_UDP == ip_header.protocol:
                self.stats.udp_packets += 1
