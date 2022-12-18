
def unpack_collection():
    records = [
        ('foo', 1, 2),
        ('bar', 'hello'),
        ('foo', 3, 4),
    ]

    def do_foo(x, y):
        print('foo', x, y)

    def do_bar(s):
        print('bar', s)

    for tag, *args in records:
        if tag == 'foo':
            do_foo(*args)
        elif tag == 'bar':
            do_bar(*args)


def Simple_Examples():
    records = ('Dave', 'dave@example.com', '773-555-1212', '847-555-1212')
    name, email, *phone_numbers = records

    print(name, email)
    print()

    *trailing, current = [10, 8, 7, 1, 9, 5, 10, 3]
    print(trailing)
    print(current)


def Unpack_String_Parts():
    line = 'nobody:*:-2:-2:Unprivileged User:/var/empty:/usr/bin/false'
    uname, *fields, homedir, sh = line.split(':')

    print(uname)
    print(homedir)
    print(sh)



if __name__ == '__main__':
    # Simple_Examples()
    # unpack_collection()
    Unpack_String_Parts()
