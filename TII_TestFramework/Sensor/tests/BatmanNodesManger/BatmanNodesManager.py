from __future__ import annotations

import binascii
import socket
import struct
import subprocess
import sys
import six
import time

from threading import Thread
from collections import defaultdict
from typing import List, Dict, Set, Tuple

from ARPHeader import ARPHeader
from EthernetHeader import EthernetHeader
from IPUtils import IPUtils
from Constants import EthernetProtocolIDs

ETHERNET_HEADER_LEN: int = 14
BROADCAST_MAC: str = 'ff:ff:ff:ff:ff:ff'


class ARPScanner(object):

    def __init__(self):
        # TODO: Rename
        self.results: Dict[bytes, bytes] = {}

        # TODO: Need to get them automatically:
        # TODO: Get interface name from 'batctl if'
        self.INTERFACE_NAME: str = 'wlp4s0'
        self.INTERFACE_MAC_ADDR: str = 'a8:93:4a:4e:00:6b'
        self.INTERFACE_IP_ADDR: str = '192.168.0.184'
        self.APR_SCAN_START_ADDR: str = '192.168.0.0'

        # TODO: Check if its OK to read and write from the same socket
        self.sock = ARPScanner.create_raw_socket()
        self.sock.bind((self.INTERFACE_NAME, 0))

    @staticmethod
    def create_raw_socket() -> socket:
        try:  # create an INET, raw socket
            sock: socket = socket.socket(socket.AF_PACKET, socket.SOCK_RAW, socket.ntohs(0x0003))
            return sock
        except socket.error as error:
            # TODO: Add logging
            print(f'Socket could not be created. Error: {error}')
            sys.exit()

    @staticmethod
    def mac_bytes_2_str(mac: bytes) -> str:
        return ':'.join('%02x' % i for i in six.iterbytes(mac))

    def broadcast_requests(self):
        dest_ip_start: int = IPUtils.IP2Int_2(self.APR_SCAN_START_ADDR)

        eth_hdr: EthernetHeader = EthernetHeader().set_destination_mac(BROADCAST_MAC) \
            .set_source_mac(self.INTERFACE_MAC_ADDR).set_protocol(EthernetProtocolIDs.ETH_P_ARP)

        arp_hdr = ARPHeader().set_sender_ip(self.INTERFACE_IP_ADDR).set_sender_mac(self.INTERFACE_MAC_ADDR)

        for i in range(256):
            target_id: str = IPUtils.Int2IP(dest_ip_start + i)
            arp_hdr.set_target_ip(target_id)  # TODO: Create func to accept INT instead of STR
            packet: bytes = eth_hdr.data + arp_hdr.data
            self.sock.send(packet)

    def wait_for_apr_reply(self, mac_list: List[str]):

        mac_list_bytes: Set[bytes] = {ARPHeader.str_2_mac(m) for m in mac_list}
        ARP_TYPE: int = socket.ntohs(EthernetProtocolIDs.ETH_P_ARP)
        while True:
            recv: Tuple = self.sock.recvfrom(65565)
            packet: bytes = recv[0]
            ethernet_header: EthernetHeader = EthernetHeader.create(packet[: ETHERNET_HEADER_LEN])

            if ethernet_header.protocol == ARP_TYPE:
                arp: ARPHeader = ARPHeader.create(packet[ETHERNET_HEADER_LEN: 28 + ETHERNET_HEADER_LEN])

                if not arp.is_request() and arp.sender_mac in mac_list_bytes:
                    self.results[arp.sender_mac] = arp.sender_ip
                    # TODO: need somehow to STOP the thread

    def scan_arp(self):
        macs: List[str] = ['f4:8c:eb:00:b8:61', 'a8:93:4a:4e:00:6b', 'f4:8c:eb:a4:68:d7', '60:32:b1:ad:d6:99',
                           'f4:8c:eb:17:6c:a9', '78:98:e8:0d:b6:a9']

        self.results.clear()

        # TODO: Add socket wait/read timeout
        thread = Thread(target=self.wait_for_apr_reply, args=(macs, ))
        thread.start()

        time.sleep(0.5)

        self.broadcast_requests()

        time.sleep(0.5)

        for mac, ip in self.results.items():
            sender_ip: str = socket.inet_ntoa(struct.pack('4s', ip))
            sender_mac_str: str = self.mac_bytes_2_str(mac)
            print(f"Reply: {sender_ip} is-at {sender_mac_str}")


class Node(object):

    def __init__(self,
                 mac: str = "00:00:00:00:00:00",
                 iface: str = "lo",
                 ip_addr: str = None):
        self.mac_address: str = mac
        self.interface_name: str = iface

        # Shall be searched using the ARP scanning:
        self.ip_address: str = ip_addr

        # True if its available as the BATMAN neighbour (according the 'batctl n' result):
        self.status: bool = True

    # TODO: Check for performance [find and use fastest implementation]
    @staticmethod
    def str_2_mac(mac_address: str) -> bytes:
        return binascii.unhexlify(mac_address.replace(':', ''))

    def get_mac_as_bytes(self) -> bytes:
        return self.str_2_mac(self.mac_address)

    def __str__(self) -> str:
        return f'Node ({self.mac_address}, {self.interface_name}, {self.ip_address}, {self.status})'

    def __repr__(self) -> str:
        return str(self)


# TODO: Delete node
class BatmanWrapper(object):
    GET_NODES_CMD: str = 'batctl n -H'

    def __init__(self):
        self.nodes: Dict[str, Node] = defaultdict(Node)

    # TODO: Refactor | Move ---> Utils
    @staticmethod
    def run_cmd(cmd: str) -> List:
        try:
            lines: List[str] = []
            proc = subprocess.Popen(cmd.split(),
                                    text=True,
                                    shell=False,
                                    stdout=subprocess.PIPE,
                                    stderr=subprocess.STDOUT)
            while True:  # TODO: get all output or line by line
                output_line = proc.stdout.readline()
                if not output_line:
                    break
                lines.append(str(output_line.rstrip()).strip("b'").replace('\t', ''))

        except OSError as exc:
            raise RuntimeError("Can't run process. Error code = {0}".format(exc))

        proc.wait()
        # print(proc.poll()) # TODO: Check results?
        return lines

    @staticmethod
    def get_batman_nodes() -> List[Node]:
        cmd_lines: List[str] = BatmanWrapper.run_cmd(BatmanWrapper.GET_NODES_CMD)
        nodes_list: List[Node] = []
        for line in cmd_lines:
            iface, mac, *other = line.split(maxsplit=3)
            nodes_list.append(Node(mac, iface))

        return nodes_list

    def validate_available_nodes(self) -> bool:
        update_required: bool = False
        nodes_list: List[Node] = BatmanWrapper.get_batman_nodes()
        for node in nodes_list:
            if node.mac_address not in self.nodes:
                self.nodes[node.mac_address] = node
                update_required = True

        # Mark all nodes missing in 'nodes_list' with node.status = False
        active_nodes_macs: Set[str] = {n.mac_address for n in nodes_list}
        for node in self.nodes.values():
            if node.mac_address not in active_nodes_macs:
                node.status = False

        return update_required

    def try_find_IPs(self):
        node_to_inspect: Dict[str, Node] = {k: v for k, v in self.nodes.items() if v.ip_address is None}
        print(node_to_inspect)

    # TODO: Remove
    def debug(self):
        for n, v in self.nodes.items():
            print(n, v)


def run_cms():
    batman: BatmanWrapper = BatmanWrapper()

    while True:
        print(batman.validate_available_nodes())
        time.sleep(1)


if __name__ == '__main__':
    ARPScanner().scan_arp()
    # run_cms()
