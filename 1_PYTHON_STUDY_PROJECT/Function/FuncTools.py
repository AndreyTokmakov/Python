import operator

import functools;
from functools import lru_cache
from functools import wraps

counter = 0


@lru_cache(maxsize=32)
def InokeLimiter():
    global counter
    counter += 1
    print("--> InokeLimiter()")


def LRU_Cache_Test():
    n = 0
    for _ in range(0, 100):
        print("Calling InokeLimiter()")
        InokeLimiter()
        n += 1

    print("Counter = ", counter, ". Called counter = ", n)


# Partial functools tests;
def PartialTest():
    def add(x, y):
        return x + y

    part_add = functools.partial(add, 2)
    print(part_add(8))


def FilterMap_Reduce():
    summa = functools.reduce(lambda a, x: a + x, [0, 1, 2, 3, 4])
    print(summa)

    mult = functools.reduce(lambda a, b: a * b, [1, 2, 3, 4])
    print(mult)


def FilterMap_Reduce_MinMax():
    numbers = [1, 3, 5, 6, 2, ]

    # using reduce to compute sum of list 
    print("The sum of the list elements is : ", end="")
    print(functools.reduce(lambda a, b: a + b, numbers))

    # using reduce to compute maximum element from list 
    print("The maximum element of the list is : ", end="")
    print(functools.reduce(lambda a, b: a if a > b else b, numbers))


def FilterMap_Reduce_Operator():
    numbers = [1, 3, 5, 6, 2, ]

    # using reduce to compute sum of list using operator functions 
    print("The sum of the list elements is : ", end="")
    print(functools.reduce(operator.add, numbers))

    # using reduce to compute product using operator functions 
    print("The product of list elements is : ", end="")
    print(functools.reduce(operator.mul, numbers))

    # using reduce to concatenate string 
    print("The concatenated product is : ", end="")
    print(functools.reduce(operator.add, ["geeks", "for", "geeks"]))


def logged(func):
    @wraps(func)
    def with_logging(*args, **kwargs):
        print(func.__name__ + " was called")
        return func(*args, **kwargs)

    return with_logging


@logged
def f(x):
    return x + x * x


def Wraps_Tests():
    print(f.__name__)  # prints 'f'
    print(f.__doc__)  # prints 'does some math'


def GetValue(a: int, b: int) -> int:
    return a + b


def Partial_Tests():
    result = functools.partial(GetValue, 10)
    print(result(15))


if __name__ == '__main__':
    # LRU_Cache_Test()
    # PartialTest()

    FilterMap_Reduce()
    # FilterMap_Reduce_MinMax()
    # FilterMap_Reduce_Operator()

    # Wraps_Tests()
    # Partial_Tests()
