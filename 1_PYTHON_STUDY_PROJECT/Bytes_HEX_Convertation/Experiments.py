import binascii

import six

bytes_to_hex_str = lambda b: ' '.join('%02x' % i for i in six.iterbytes(b))

mac_addr_bytex_2_str = lambda b: ':'.join('%02x' % i for i in six.iterbytes(b))


def hex_2_str_Tests():
    print(bytes_to_hex_str(b'jkl') == '6a 6b 6c')
    print(mac_addr_bytex_2_str(b'\x11"3DUf') == '11:22:33:44:55:66')


def mac_addr_Test():
    mac_str: str = '11:22:33:44:55:66'
    mac_bytes: bytes = binascii.unhexlify(mac_str.replace(':', ''))

    print(mac_bytes)
    print(mac_addr_bytex_2_str(mac_bytes))


if __name__ == '__main__':
    # hex_2_str_Tests()
    mac_addr_Test()
