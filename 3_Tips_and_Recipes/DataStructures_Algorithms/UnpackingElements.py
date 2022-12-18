
record = ('Dave', 'dave@example.com', '773-555-1212', '847-555-1212')


def unpack_test1():
    name, email, *phone_numbers = record
    print(name, '\n', email, '\n', phone_numbers)


def unpack_test2():
    *beg_elements, before_last, last = record
    print(beg_elements, '\n', before_last, '\n', last)


if __name__ == '__main__':
    unpack_test1()
    # unpack_test2()