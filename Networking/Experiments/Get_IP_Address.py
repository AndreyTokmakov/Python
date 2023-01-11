import fcntl
import socket
import struct
from typing import Dict, List

import netifaces
import psutil
import uuid
import re


def get_network_interfaces():
    addrs = psutil.net_if_addrs()
    print(addrs.keys())


'''
def get_ip_address_from_socket(ifname: str):
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    return socket.inet_ntoa(fcntl.ioctl(s.fileno(), 0x8915, struct.pack('256s', ifname[:15]))[20:24])
'''


def get_interfaces_IP_addresses():
    addresses: Dict[str, List] = psutil.net_if_addrs()
    for iface_name, attributes in addresses.items():
        print(iface_name)
        for attr in attributes:
            print('\t', attr)
        print()


# br-lan

def get_addresses_by_name(iface_nane: str):
    iface_attributes: List = psutil.net_if_addrs()[iface_nane]
    for attr in iface_attributes:
        # print(iface_attributes)
        if socket.AddressFamily.AF_INET == attr.family:
            print('\t', attr.address)


def get_network_physical_address(netInterfaceName):
    iface = netifaces.ifaddresses(netInterfaceName)
    print(iface)


def get_mac():
    mac = uuid.getnode()
    print(':'.join(re.findall('..', '%012x' % mac)))


def get_info_per_interface():
    for iface in netifaces.interfaces():
        print(iface)
        print(netifaces.ifaddresses(iface))


if __name__ == "__main__":
    # get_network_interfaces()
    # get_interfaces_IP_addresses()
    get_addresses_by_name('enp0s31f6')

    # get_network_physical_address("wlp4s0")
    # get_mac()

    # get_info_per_interface()
