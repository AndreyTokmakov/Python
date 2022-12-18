
def simple_test():
    data = b'shave and a haircut, two bits'
    view = memoryview(data)
    chunk = view[12:19]

    print(chunk)
    print('Size:', chunk.nbytes)
    print('Data in view: ', chunk.tobytes())
    print('Underlying data:', chunk.obj)


def simple_test2():
    # random bytearray
    random_byte_array = bytearray('ABC', 'utf-8')
    mv = memoryview(random_byte_array)

    # access memory view's zeroth index
    print(mv[0])

    # create byte from memory view
    print(bytes(mv[0:2]))

    # create list from memory view
    print(list(mv[0:3]))


if __name__ == '__main__':
    # simple_test()
    simple_test2()

