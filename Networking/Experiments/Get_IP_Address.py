import netifaces
import psutil
import uuid
import re


def get_network_interfaces():
    addrs = psutil.net_if_addrs()
    print(addrs.keys())


def get_network_physical_address(netInterfaceName):
    iface = netifaces.ifaddresses(netInterfaceName)
    print(iface)


def get_mac():
    mac = uuid.getnode()
    print(':'.join(re.findall('..', '%012x' % mac)))


if __name__ == "__main__":
    # get_network_interfaces()
    # get_network_physical_address("wlp4s0")
    # get_mac()

    for iface in netifaces.interfaces():

        print(netifaces.ifaddresses(iface))
