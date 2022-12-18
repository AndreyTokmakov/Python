import random

import numpy
import numpy as np


def CreateMatrix():
    matrix = np.array([[0, 0],
                       [0, 1],
                       [3, 0]])
    print(matrix)


def LinSpace():
    rotation_values = np.linspace(-45.0, 45.0, 45)
    print(rotation_values)


def Reshape_Tests():
    data = np.array([[1, 1, 1, 1], [2, 2, 2, 2], [3, 3, 3, 3]], order='C')
    print(data)

    data1 = np.reshape(data, (4, 3))
    print("\nreading by lines:");
    print(data1)

    data2 = np.reshape(data, (4, 3), order='F')
    print("\nreading by columns:");
    print(data2)


def Zeros():
    centroids_lower = np.zeros(5, int)
    print(centroids_lower)
    print(np.zeros((1, 2), dtype=np.int32))


def Zeros2():
    nums = [3, 3, 3]
    print(np.zeros(nums, dtype=numpy.int32))


def Ones():
    nums = [3, 3, 3]
    print(np.ones(nums, dtype=numpy.int32))


def Reverse_Array():
    data = np.array([7, 5, -3, 4, 1])
    print(data)

    reversed_data = data[::-1]
    print(reversed_data)


def Square():
    a = np.array([1, 2, 3, 4, 5, 6, 7])
    b = np.array([2, 3, 4, 5, 6, 7, 8])
    c = np.array([1, 2, 3])

    ab = b - a
    print(ab)

    c_squared = np.square(c).sum()
    print(c_squared)

    ab_squared = np.square(b - a).sum()
    print(ab_squared)


def Mean():
    a = np.array([1, 2, 3, 4, 5, 6, 7])
    n = np.size(a)
    print(f'a = {n}')

    mean = np.mean(a)
    print(f'mean = {mean}')


def Max():
    a = np.array([1, 2, 3, 4, 5, 6, 7])
    max = np.max(a)
    print(f'max = {max}')


def Sum():
    a = np.array([1, 2, 3])
    b = np.sum(a)
    print(b)


def Multipy():
    a = np.array([1, 2, 3])
    b = np.array([3, 4, 5])
    c = a * b
    print(c)


def Norm():
    a = np.array([1, 2, 3])
    x = a / np.linalg.norm(a)
    print(x)


def Tests():
    a = np.array([1, 2, 3])
    a[1] = 23

    print(a)


def Concatinate():
    a = np.array([1, 2, 3])
    b = np.array([4, 5, 6])
    c = np.array([7, 8, 9])

    d = np.array([])
    list = [a, b, c]
    for arr in list:
        d = np.concatenate([d, arr])

    print(d)


def Concatinate_2D():
    d = np.zeros(shape=(0, 3))
    a = np.array([1, 2, 3])
    b = np.array([4, 5, 6])
    c = np.array([7, 8, 9])

    list = [a, b, c]
    for arr in list:
        d = np.vstack([d, arr])

    print(d)


def Arrays_Test_2D():
    a = np.array([[1, 2, 3]])
    print(a)

    b = [4, 5, 6]
    c = np.vstack([a, b])

    print(c)


def Transform(data: np.array):
    return data * [1, 1, 2]


def ApplyFunc():
    a = np.array([[1, 2, 3], [1, 2, 3]])
    b = Transform(a)
    print(b)


def ApplyFunc2():
    matrix = np.array([[1, 2, 3],
                       [4, 5, 6],
                       [7, 8, 9]])
    print(matrix)

    add_100 = lambda i: i + 100
    vectorized_add_100 = np.vectorize(add_100)
    vectorized_add_100(matrix)

    print(vectorized_add_100(matrix))


def ApplyFunc3():
    matrix = np.array([[1, 2, 3],
                       [4, 5, 6],
                       [7, 8, 9]])
    print(matrix)
    print(matrix + 100)


if __name__ == '__main__':
    # CreateMatrix()

    # Zeros()
    # Zeros2()

    Ones()

    # LinSpace()
    # Reshape_Tests()
    # Square()
    # Reverse_Array();

    # Mean();
    # Max()

    # Multipy();
    # Sum()

    # Norm();

    # ApplyFunc();
    # ApplyFunc2();
    # ApplyFunc3();

    # Concatinate()
    # Concatinate_2D()

    # Arrays_Test_2D();

    # Tests()
