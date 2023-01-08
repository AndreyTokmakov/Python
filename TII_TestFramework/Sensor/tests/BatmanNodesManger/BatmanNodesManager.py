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


class CMSData(object):
    INTERFACE_NAME: str = 'wlp1s0'
    INTERFACE_MAC_ADDR: str = '00:30:1a:4f:8d:c4'
    INTERFACE_IP_ADDR: str = '192.168.1.5'
    APR_SCAN_START_ADDR: str = '192.168.1.0'


class LocalData(object):
    INTERFACE_NAME: str = 'wlp0s20f3'
    INTERFACE_MAC_ADDR: str = 'bc:6e:e2:03:74:ba'
    INTERFACE_IP_ADDR: str = '192.168.57.54'
    APR_SCAN_START_ADDR: str = '192.168.57.0'


# data = LocalData()
data = CMSData()


class ARPScanner(object):

    def __init__(self):
        # TODO: Rename
        self.results: Dict[bytes, bytes] = {}

        # TODO: Need to get them automatically:
        # TODO: Get interface name from 'batctl if'
        self.INTERFACE_NAME: str = data.INTERFACE_NAME
        self.INTERFACE_MAC_ADDR: str = data.INTERFACE_MAC_ADDR
        self.INTERFACE_IP_ADDR: str = data.INTERFACE_IP_ADDR
        self.APR_SCAN_START_ADDR: str = data.APR_SCAN_START_ADDR

        # TODO: Check if its OK to read and write from the same socket
        self.sock = ARPScanner.create_raw_socket()
        self.sock.bind((self.INTERFACE_NAME, 0))

        # Maximum time to wait for ARP response packets:
        self.max_timeout: float = 3.0

    @staticmethod
    def create_raw_socket() -> socket:
        try:  # create an INET, raw socket
            sock: socket = socket.socket(socket.AF_PACKET, socket.SOCK_RAW, socket.ntohs(0x0003))

            # Set receive timeout to 0.1 sec
            timeval = struct.pack('ll', 0, 250000)
            sock.setsockopt(socket.SOL_SOCKET, socket.SO_RCVTIMEO, timeval)

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

        mac_list_len: int = len(mac_list_bytes)
        start: float = time.time()
        while True:
            try:
                recv: Tuple = self.sock.recvfrom(65565)
                packet: bytes = recv[0]
                ethernet_header: EthernetHeader = EthernetHeader.create(packet[: ETHERNET_HEADER_LEN])

                if ethernet_header.protocol == ARP_TYPE:
                    arp: ARPHeader = ARPHeader.create(packet[ETHERNET_HEADER_LEN: 28 + ETHERNET_HEADER_LEN])

                    if not arp.is_request() and arp.sender_mac in mac_list_bytes:
                        self.results[arp.sender_mac] = arp.sender_ip
                        # Check if we've got all replies we needed:
                        if mac_list_len == len(self.results.keys()):
                            break

            except Exception as exc:
                pass
            if (time.time() - start) >= self.max_timeout:
                break

    def scan_arp(self, macs: List[str]) -> Dict[bytes, bytes]:
        self.results.clear()

        thread = Thread(target=self.wait_for_apr_reply, args=(macs,))
        thread.start()

        time.sleep(0.25)

        self.broadcast_requests()
        thread.join()

        return self.results


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
        self.apr_scanner: ARPScanner = ARPScanner()

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
        # Get the B.A.T.M.A.N neighbourhoods + add missing to internal storage:
        nodes_list: List[Node] = BatmanWrapper.get_batman_nodes()
        for node in nodes_list:
            if node.mac_address not in self.nodes:
                self.nodes[node.mac_address] = node

        # Mark all nodes missing in 'nodes_list' with node.status = False
        active_nodes_macs: Set[str] = {n.mac_address for n in nodes_list}
        for node in self.nodes.values():
            if node.mac_address not in active_nodes_macs:
                node.status = False

        # Do we have some node without IP address? :
        has_node_without_ip: bool = any(node.ip_address is None for node in self.nodes.values())

        return has_node_without_ip

    def try_find_IPs(self):
        macs_to_inspect: List[str] = [k for k, v in self.nodes.items() if v.ip_address is None]
        scan_results: Dict[bytes, bytes] = self.apr_scanner.scan_arp(macs_to_inspect)

        # FIXME: Refactor??? Str -> Bytes
        for mac, ip in scan_results.items():
            sender_ip: str = socket.inet_ntoa(struct.pack('4s', ip))
            sender_mac_str: str = self.apr_scanner.mac_bytes_2_str(mac)
            # node: Node = self.nodes.get(sender_mac_str, Node())
            self.nodes[sender_mac_str].ip_address = sender_ip
            print(f"ARP Reply: {sender_mac_str} ==>  {sender_ip}")

    def print_nodes_table(self):
        for node in self.nodes.values():
            print(f'{node.mac_address}  {node.ip_address}  {node.interface_name}  {node.status}')


def run_cms():
    batman: BatmanWrapper = BatmanWrapper()

    start: float = time.time()
    while True:
        update_required: bool = batman.validate_available_nodes()
        if update_required:
            batman.try_find_IPs()
        print(f'update_required: {update_required}')
        time.sleep(1)

        if (time.time() - start) >= 60:  # 1 min has passed
            start = time.time()
            batman.print_nodes_table()


def run_local():
    # macs: List[str] = ['e8:eb:34:bf:80:2f', 'a8:93:4a:4e:00:6b', 'f4:8c:eb:a4:68:d7']
    macs: List[str] = ['e8:eb:34:bf:80:2f', 'e8:eb:34:bf:95:2f', '68:7d:b4:fd:9a:ab']

    apr_scanner: ARPScanner = ARPScanner()
    scan_results: Dict[bytes, bytes] = ARPScanner().scan_arp(macs)

    for mac, ip in scan_results.items():
        sender_ip: str = socket.inet_ntoa(struct.pack('4s', ip))
        sender_mac_str: str = apr_scanner.mac_bytes_2_str(mac)
        print(f"Reply: {sender_ip} is-at {sender_mac_str}")


if __name__ == '__main__':
    run_local()
    run_cms()
