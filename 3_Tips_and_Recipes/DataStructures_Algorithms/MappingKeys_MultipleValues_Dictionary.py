from collections import defaultdict


def DictTest1():
    d = defaultdict(list)

    d['a'].append(1)
    d['a'].append(2)
    d['a'].append(2)
    d['b'].append(4)

    print(d)


def DictTest_Set():
    d = defaultdict(set)

    d['a'].add(1)
    d['a'].add(2)
    d['a'].add(2)
    d['b'].add(4)

    print(d)


def DictTest_Regular():
    d = {}

    # A regular dictionary
    d.setdefault('a', []).append(1)
    d.setdefault('a', []).append(2)
    d.setdefault('b', []).append(4)

    print(d)


if __name__ == '__main__':
    # DictTest1()
    # DictTest_Set()
    DictTest_Regular()
