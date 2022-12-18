from typing import List
from itertools import dropwhile


def is_positive(n):
    return n > 0


if __name__ == '__main__':
    value: List[int] = [5, 6, 4, 3, -8, -4, 2]
    result = list(dropwhile(is_positive, value))

    print(value, " --> ", result)