import datetime
from datetime import timedelta, date
from random import random
from typing import List


class DateIterable(object):

    def __init__(self, start_date, end_date) -> None:
        # initializing the start and end dates
        self.__start_date: date = start_date
        self.__end_date: date = end_date

    def __iter__(self):
        # returning __iter__ object
        return self

    def __next__(self) -> datetime.date:
        # comparing present_day with end_date, if present_day greater than end_date stopping the iteration
        if self.__start_date >= self.__end_date:
            raise StopIteration
        dt = self.__start_date
        self.__start_date += timedelta(days=1)
        return dt


def Iterate_Dates() -> None:
    for day in DateIterable(date(2020, 1, 1), date(2020, 1, 6)):
        print(day)


def Print_as_List():
    obj: DateIterable = DateIterable(date(2020, 1, 1), date(2020, 1, 6))
    print(list(obj))


class RandomIncrease(object):

    def __init__(self, quantity: int) -> None:
        self.__quantity: int = quantity
        self.cur = 0

    def __iter__(self):
        return self

    def __next__(self):
        if self.__quantity > 0:
            self.cur += random()
            self.__quantity -= 1
            return round(self.cur, 2)
        else:
            raise StopIteration


def Random_Increase_Iterator_Test():
    iterator = RandomIncrease(5)
    for i in iterator:
        print(i)


if __name__ == '__main__':
    # Iterate_Dates()
    # Print_as_List()

    Random_Increase_Iterator_Test()