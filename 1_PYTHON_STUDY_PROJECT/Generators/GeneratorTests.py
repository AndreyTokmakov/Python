def Test1():
    ints = [x ** 2 for x in range(5)]
    print(ints);

    ints2 = [i for i in range(2, 8)]
    print(ints2);


def Test2():
    a = [1, 2, 3]
    a = [i + 10 for i in a]
    print(a);


def Test3():
    a = [i for i in range(30, 250) if i % 30 == 0 or i % 31 == 0]
    print(a);


def SquareGeneratorTest():
    def square_num(nums):
        for i in nums:
            yield (i ** 2)

    for i in square_num([1, 2, 3, 4]):
        print(i)


def Filter_List():
    list = [1, 2, 3, 4, 5, 6, 7, 8, 9];
    print(list)
    list = [i for i in list if 0 == i % 2]
    print(list)


############################## MAIN ########################

if __name__ == '__main__':
    # Test1()
    # SquareGeneratorTest();
    # Test2();
    # Test3();

    Filter_List();

    '''
    for i in [n for n in range(0, 10) if n %2 ==0]:
        print(i)
    '''
