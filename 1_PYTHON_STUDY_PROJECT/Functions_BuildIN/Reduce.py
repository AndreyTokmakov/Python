
from functools import reduce


def reduce_test_1():
    sum = lambda a, b: a + b
    x = reduce(sum, [23, 21, 45, 98])
    print(x)


if __name__ == '__main__':
    reduce_test_1()