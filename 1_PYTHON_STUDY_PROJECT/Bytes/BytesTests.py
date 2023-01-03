def Test_1():
    print(b"abcde".decode("utf-8"));


def String_2_Bytes():
    input_string = "Some_test"
    print(bytes(input_string, 'utf-8'))


def list_of_bytes_2_bytes():
    lst = [b'Python', b'is', b'beautiful']

    print(b' '.join(lst))  #  b'Python is beautiful'

def list_of_bytes_2_bytes2():
    byte_data = [65, 33]
    strings = b" ".join(map(bytes, byte_data))
    print(strings)


if __name__ == '__main__':
    # Test_1();
    # String_2_Bytes()

    # list_of_bytes_2_bytes()
    # list_of_bytes_2_bytes2()

    print(type(b'A'))

    print(b'A')


