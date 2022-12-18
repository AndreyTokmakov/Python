from itertools import islice


def fibonachi():
    a, b = 0, 1
    while True:
        yield b
        a, b = b, a + b


def fibonachi_recursive(n):
    if n <= 0:  # base case 1
        return 0
    if n <= 1:  # base case 2
        return 1
    else:  # recursive step
        return fibonachi_recursive(n - 1) + fibonachi_recursive(n - 2)


calculated = {}


def fibonachi_dynamic(n):
    if n == 0:  # base case 1
        return 0
    if n == 1:  # base case 2
        return 1
    elif n in calculated:
        return calculated[n]
    else:  # recursive step
        calculated[n] = fibonachi_dynamic(n - 1) + fibonachi_dynamic(n - 2)
        return calculated[n]


if __name__ == '__main__':
    result = list(islice(fibonachi(), 9))
    print(result)
