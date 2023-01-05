import binascii
import codecs


def str_to_bin_and_back():
    text: str = 'Hello World'

    string_bytes: bytes = text.encode('utf-8')
    hex_value: bytes = binascii.hexlify(string_bytes)

    print(f"HEX value of the string '{text}' is {hex_value}")

    bytesStr = codecs.decode(hex_value, 'hex_codec')
    text_orig: str = bytesStr.decode('utf-8')
    print(f"Text value of the HEX data {hex_value} is '{text_orig}'")


def str_to_bin_and_back_2():
    text: str = 'Hello World'

    string_bytes: bytes = text.encode('utf-8')
    hex_value: bytes = binascii.hexlify(string_bytes)

    print(f"HEX value of the string '{text}' is {hex_value}")

    text_orig: str = bytes.fromhex(hex_value.decode()).decode()
    print(f"Text value of the HEX data {hex_value} is '{text_orig}'")


def str_to_bin_and_back_3():
    text: str = 'Hello World'

    string_bytes: bytes = text.encode('utf-8')
    hex_value: bytes = binascii.hexlify(string_bytes)

    print(f"HEX value of the string '{text}' is {hex_value}")

    text_orig: str = binascii.unhexlify(hex_value.decode()).decode()
    print(f"Text value of the HEX data {hex_value} is '{text_orig}'")


if __name__ == '__main__':
    # str_to_bin_and_back()
    # str_to_bin_and_back_2()
    str_to_bin_and_back_3()
    pass
