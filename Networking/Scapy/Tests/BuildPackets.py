from scapy.layers.inet import IP, TCP
from scapy.layers.l2 import Ether
from scapy.utils import hexdump


def ip_test():
    packet = IP(src="192.168.1.0",
                dst="8.8.8.8",
                ttl=10)

    # packet.src = "192.168.1.0"

    packet.show()


def hexdump_packet():

    packet = Ether()/IP(dst="www.slashdot.org")/TCP()/b"GET /index.html HTTP/1.0 \n\n"
    packet.show()

    print('_'.join(['' for _ in range(120)]))
    print(hexdump(packet))


if __name__ == "__main__":
    # ip_test()
    hexdump_packet()
