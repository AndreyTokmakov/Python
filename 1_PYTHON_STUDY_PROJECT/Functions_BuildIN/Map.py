
class Utils:
    @staticmethod
    def square(a):
        return a * a

    @staticmethod
    def sum(a, b):
        return a + b


def map_test1():
    numbers = [1, 2, 3, 4]
    x = map(Utils.square, numbers)
    print(x)
    print(list(x))


def map_test2():
    x = map(Utils.sum, [2, 4, 5], [1, 2, 3])
    print(x)
    print(list(x))


def map_lambda():
    tup = (5, 7, 22, 97, 54, 62, 77, 23, 73, 61)
    foo = lambda x: x+3

    newtuple = tuple(map( foo, tup))
    print(newtuple)


if __name__ == '__main__':
    # map_test1()
    # map_test2()
    map_lambda()
