from typing import List


def any_test_1():
    numbers = [1, 2, 3, 4, 5, 6]
    result: bool = any(x > 5 for x in numbers)
    print(result)


def __contains_any_std(l1: List, l2: List) -> bool:
    for v1 in l1:
        if v1 in l2:
            return True
    return False


def __contains_any(l1: List, l2: List) -> bool:
    return any(elem in l1 for elem in l2)


def contains_any_test():
    list1 = [1, 2, 3, 4]
    list2 = [4, 5, 6, 7, 8, 9]

    print(__contains_any(list1, list2))
    print(__contains_any_std(list1, list2))


if __name__ == '__main__':
    # any_test_1()
    contains_any_test()
