from __future__ import annotations

import binascii
import subprocess
import time
from collections import defaultdict
from typing import List, Dict, Set


class TestData(object):
    cmd_outputs_list: List[List[str]] = [
        ['       wlp1s0\t  00:30:1a:4e:fa:53\n    0.052s',
         '       wlp1s0\t  01:31:2a:6e:ba:13\n    0.302s'],
        ['       wlp1s0\t  00:30:1a:4e:fa:53\n    0.052s',
         '       wlp1s0\t  01:31:2a:6e:ba:13\n    0.302s',
         '       wlp1s0\t  01:31:2a:6e:ba:22\n    0.222s'],
        ['       wlp1s0\t  00:30:1a:4e:fa:53\n    0.052s',
         '       wlp1s0\t  01:31:2a:6e:ba:13\n    0.302s',
         '       wlp1s0\t  01:31:2a:6e:ba:22\n    0.222s',
         '       wlp1s0\t  01:31:2a:6e:ba:33\n    0.333s'],
    ]

    def __init__(self):
        self.index: int = 0

    def get_test_output(self) -> List[str]:
        if self.index >= len(self.cmd_outputs_list):
            self.index = 0
        result: List[str] = TestData.cmd_outputs_list[self.index]
        self.index += 1
        return result


test_data: TestData = TestData()


class Node(object):

    def __init__(self,
                 mac: str = "00:00:00:00:00:00",
                 iface: str = "lo",
                 ip_addr: str = None):
        self.mac_address: str = mac
        self.interface_name: str = iface
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
        return test_data.get_test_output()
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


def run_local():
    batman: BatmanWrapper = BatmanWrapper()

    batman.validate_available_nodes()
    batman.validate_available_nodes()
    batman.validate_available_nodes()

    print()
    batman.debug()

    batman.validate_available_nodes()

    print()
    # batman.debug()

    batman.nodes['01:31:2a:6e:ba:13'].ip_address = "22"
    batman.nodes['01:31:2a:6e:ba:22'].ip_address = "22"
    batman.nodes['01:31:2a:6e:ba:33'].ip_address = "33"

    batman.try_find_IPs()


if __name__ == '__main__':
    run_local()
    # run_cms()
