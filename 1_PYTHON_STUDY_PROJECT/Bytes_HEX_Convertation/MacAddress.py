import binascii
import six

mac_addr_bytex_2_str = lambda b: ':'.join('%02x' % i for i in six.iterbytes(b))


def mac_addr_Test():
    mac_str: str = '11:22:33:44:55:66'
    mac_bytes: bytes = binascii.unhexlify(mac_str.replace(':', ''))

    print(mac_bytes)
    print(mac_addr_bytex_2_str(mac_bytes))


if __name__ == '__main__':
    mac_addr_Test()
