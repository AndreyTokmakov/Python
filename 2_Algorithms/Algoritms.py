def __FindMissing(full_set, partial_set):
    missing_array = set(full_set) - set(partial_set)
    assert (1 == len(missing_array))
    print(list(missing_array)[0])


def FindMissing():
    __FindMissing([1, 2, 3, 4, 5], [1, 2, 4, 5])


def __SmallestMissingPositiveNumber(A):
    min_element = min(A)
    max_element = max(A)
    if 1 > max_element or min_element > 1:
        return 1

    set_list = set(A)
    for i in range(max(1, min_element), max_element):
        if i not in set_list:
            return i
    return max_element + 1


def SmallestMissingPositiveNumber():
    a = [1, 3, 6, 4, 1, 2]
    print(__SmallestMissingPositiveNumber(a))


if __name__ == '__main__':
    FindMissing()
    # SmallestMissingPositiveNumber()
