
import ctypes


if __name__ == '__main__':
    list = [1, 2, 3]
    another_list = list

    l1_addr = id(list)
    ref_count: ctypes.c_long = ctypes.c_long.from_address(l1_addr)

    print(f'Ref count: {ref_count.value}')