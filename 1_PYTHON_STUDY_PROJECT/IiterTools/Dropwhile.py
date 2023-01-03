import itertools
from typing import List
from itertools import dropwhile


def is_positive(n):
    return n > 0


def drop_while_1():
    value: List[int] = [5, 6, 4, 3, -8, -4, 2]
    result = list(dropwhile(is_positive, value))

    print(value, " --> ", result)  # [5, 6, 4, 3, -8, -4, 2]  -->  [-8, -4, 2]


def drop_while_2():
    values = [1, 2, 3, 4, 5, 6, 7, 8, 9, 10]
    it = itertools.dropwhile(lambda x: x < 7, values)
    print(values, " --> ", list(it))  # [1, 2, 3, 4, 5, 6, 7, 8, 9, 10]  -->  [7, 8, 9, 10]


if __name__ == '__main__':
    drop_while_1()
    drop_while_2()
