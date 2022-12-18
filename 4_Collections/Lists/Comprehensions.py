def list_of_pairs():
    lists = [[1, "One"], [2, "Two"], [3, "Three"]]

    print(lists[1:3])
    print([n[1] for n in lists[1:3]])


def copy_or_ref():
    lists1 = [[1, "One"], [2, "Two"], [3, "Three"]]
    lists2 = lists1[:2]

    print(lists1)
    print(lists2)

    lists2[0][1] = "One_NEW"

    print(lists1)
    print(lists2)


def copy_or_ref2():
    lists1 = [[1, "One"], [2, "Two"], [3, "Three"]]
    lists2 = lists1[:]

    print(lists1, "\n", lists2)

    lists2[0][1] = "Updated"

    print(lists1, "\n", lists2)


if __name__ == '__main__':
    # list_of_pairs()
    # copy_or_ref()
    copy_or_ref2()
