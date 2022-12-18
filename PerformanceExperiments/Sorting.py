import random
import timeit


def sort_local(n: int) -> None:
    data = [random.randint(1, 10 ** 9) for i in range(n)]
    for i in range(len(data)):
        for j in range(i, len(data)):
            if data[i] > data[j]:
                data[i], data[j] = data[j], data[i]


n1 = 100
data1 = [random.randint(1, 10 ** 9) for _ in range(n1)]


def sort_global(n2: int) -> None:
    for i in range(n2):
        data1[i] = random.randint(1, 10 ** 9)
    for i in range(len(data1)):
        for j in range(i, len(data1)):
            if data1[i] > data1[j]:
                data1[i], data1[j] = data1[j], data1[i]


if __name__ == '__main__':
    print(timeit.timeit(stmt=lambda: sort_local(100), number=10000))
    print(timeit.timeit(stmt=lambda: sort_global(100), number=10000))
