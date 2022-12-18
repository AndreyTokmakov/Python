

class Ten:
    def __get__(self, obj, objtype=None):
        return 10


class A(object):
    x = 5  # Regular class attribute
    y = Ten()  # Descriptor instance


if __name__ == '__main__':
    c = A()

    print(c.x)
    print(c.y)