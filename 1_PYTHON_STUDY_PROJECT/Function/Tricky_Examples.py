from typing import List


def make_functions():
    funks: List = list()
    for i in [1, 2, 3]:
        print(f'make_functions({i})')

        def printer():
            print(i)

        funks.append(printer)

    return funks


if __name__ == '__main__':

    functions = make_functions()
    for f in functions:
        f()
