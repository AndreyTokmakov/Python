from random import random
import collections.abc


def simpleTest():
    ints = [1, 2, 3, 4, 5, 6, 7];
    it = iter(ints)

    print(next(it))
    print(next(it))
    print(next(it))
    print(next(it))
    print(next(it))


def range_Loop_Test():
    for i in iter(range(10)):
        print(i)


def range_Loop_Test_2():
    ints = [1, 2, 3, 4, 5, 6, 7];
    iterator = iter(ints)
    done_looping = False
    while not done_looping:
        try:
            item = next(iterator);
            print(item);
        except StopIteration:
            done_looping = True
            print("STop iteration")
        else:
            # action_to_do(item)
            pass;


""""""""" SimpleIterator """""""""


class SimpleIterator:

    def __init__(self, limit):
        self.__limit = limit
        self.__counter = 0

    def __iter__(self):
        return self

    def __next__(self):
        if self.__counter < self.__limit:
            self.__counter += 1
            return self.__counter
        else:
            raise StopIteration


def SimpleIteratorTest():
    iterator = SimpleIterator(5)
    for i in iterator:
        print(i)


""""""""" RandomIncrease """""""""


class RandomIncrease:
    def __init__(self, quantity):
        self.__count = quantity
        self.__current = 0

    def __iter__(self):
        return self

    def __next__(self):
        if self.__count > 0:
            self.__current += random()
            self.__count -= 1
            return round(self.__current, 2)
        else:
            raise StopIteration


def RandIterTest():
    iterator = RandomIncrease(5)
    for i in iterator:
        print(i)


##################################################

if __name__ == '__main__':
    simpleTest()
    # range_Loop_Test();
    # range_Loop_Test_2();
    # RandIterTest();
    # SimpleIteratorTest();
