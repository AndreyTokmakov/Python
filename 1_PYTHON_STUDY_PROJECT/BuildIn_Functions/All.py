from typing import List


def all_even():
    evens, odds = [0, 2, 4, 6, 8], [1, 3, 5, 7, 9]
    print(all(x % 2 == 0 for x in evens))
    print(all(x % 2 == 0 for x in odds))


def contains_all():
    strings = ['one', 'two', ' three', 'four', 'five', 'six', 'seven']
    to_find = ['one', 'two', ' three']

    result: bool = all(elem in strings for elem in to_find)
    print(result)

    to_find.append("four1")

    result = all(elem in strings for elem in to_find)
    print(result)


if __name__ == '__main__':
    # all_even()
    contains_all()
