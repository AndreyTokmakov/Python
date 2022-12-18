def func(x):
    if x >= 3:
        return x


def Filter_Func():
    predicate = lambda x: (x >= 3)
    y = filter(predicate, (1, 2, 3, 4))
    print(list(y))


def Filter_Lambda():
    y = filter(lambda x: (x >= 3), (1, 2, 3, 4))
    print(list(y))


if __name__ == '__main__':
    Filter_Func()
    Filter_Lambda()
