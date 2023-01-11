import socket
from typing import List

import psutil


# TODO: Refactor this SINGLETON
class Configuration(object):
    __instance = None
    __constructed: bool = False

    def __init__(self):
        if not self.__constructed:  # TODO: BAD
            self.interface_name: str = "enp0s31f6"
            self.ip_address: str = "None"
            Configuration.__constructed = True  # TODO: BAD

    def __new__(cls):
        if cls.__instance is None:
            cls.__instance = super().__new__(cls)

        return cls.__instance

    def init(self) -> None:
        self.ip_address: str = Configuration.get_addresses_by_name(self.interface_name)

    @staticmethod
    def get_addresses_by_name(iface_name: str) -> str:
        iface_attributes: List = psutil.net_if_addrs().get(iface_name, [])
        for attr in iface_attributes:
            if socket.AddressFamily.AF_INET == attr.family:
                return attr.address
        raise RuntimeError(f"Failed to get '{iface_name}' IPv4 address")



if __name__ == "__main__":
    cfg1 = Configuration()
    cfg2 = Configuration()

    print(cfg1.ip_address)

    cfg1.init()

    print(cfg1.ip_address)
