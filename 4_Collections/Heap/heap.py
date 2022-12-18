import heapq


def finding_largest_1():
    nums = [1, 8, 2, 23, 7, -4, 18, 23, 42, 37, 2]

    print(heapq.nlargest(3, nums))  # Prints [42, 37, 23]
    print(heapq.nsmallest(3, nums))  # Prints [-4, 1, 2]


def finding_largest_2():
    portfolio = [{'name': 'IBM', 'shares': 100, 'price': 91.1},
                 {'name': 'AAPL', 'shares': 50, 'price': 543.22},
                 {'name': 'FB', 'shares': 200, 'price': 21.09},
                 {'name': 'HPQ', 'shares': 35, 'price': 31.75},
                 {'name': 'YHOO', 'shares': 45, 'price': 16.35},
                 {'name': 'ACME', 'shares': 75, 'price': 115.65}]

    cheap = heapq.nsmallest(3, portfolio, key=lambda s: s['price'])
    expensive = heapq.nlargest(3, portfolio, key=lambda s: s['price'])

    print("------------------- cheap -------------------\n", cheap)
    print("------------------- expensive -------------------\n", expensive)


def K_Largest_Elements():
    # initializing list
    li1 = [6, 7, 9, 4, 3, 5, 8, 10, 1]

    # using heapify() to convert list into heap
    heapq.heapify(li1)

    # using nlargest to print 3 largest numbers prints 10, 9 and 8
    print("The 3 largest numbers in list are : ", end="")
    print(heapq.nlargest(3, li1))

    # using nsmallest to print 3 smallest numbers prints 1, 3 and 4
    print("The 3 smallest numbers in list are : ", end="")
    print(heapq.nsmallest(3, li1))


if __name__ == '__main__':
    # finding_largest_1()
    # finding_largest_2()

    K_Largest_Elements()
