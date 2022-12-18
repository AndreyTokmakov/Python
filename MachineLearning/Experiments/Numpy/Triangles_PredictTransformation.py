from functools import reduce
from typing import List

import math
import matplotlib.pyplot as plt
import numpy as np

''' 
the essence of the test is to have a set of triangles (for the test) and having a set of 
transformed triangles to predict the algorithm according  to which the initial transformation occurs
'''

class Point(object):
    x = 0;
    y = 0;

    def __init__(self, a, b):
        self.x = a
        self.y = b

    def __str__(self):
        return f'({self.x}, {self.y})'


class Triangle(object):
    def __init__(self,
                 l: Point,
                 r: Point,
                 c: Point):
        self.left = l
        self.right = r
        self.center = c

    def __str__(self):
        return f'({self.x}, {self.y})'


# TODO: Params for triangle
class Coefficient(object):
    A = 0
    B = 0

    def __init__(self, a=0, b=0):
        self.A = a
        self.B = b


def VisTriangle(triangle: Triangle):
    x = [triangle.left.x, triangle.right.x, triangle.center.x]
    y = [triangle.left.y, triangle.right.y, triangle.center.y]
    plt.scatter(x, y)
    plt.show()


def PrepareRightTriangle(coef) -> Triangle:
    pt_left = Point(0, 0)
    pt_right = Point(coef, 0)
    pt_center = Point(pt_right.x / 2, coef)
    return Triangle(pt_left, pt_right, pt_center)


'''
def TransformTriangle(origin: Triangle, coef) -> Triangle:
    pt_center = Point(origin.center.x, origin.center.y * coef)
    return Triangle(origin.left, origin.right, pt_center)
'''

def GetSampleRightTriangles(count: int) -> List[Triangle]:
    list = []
    for i in np.linspace(1, 20, count):
        list.append(PrepareRightTriangle(i))
    return list


def Triangle2NumpyArray(triangle: Triangle) -> np.array:
    coords = np.array([
        triangle.left.x, triangle.left.y,
        triangle.right.x, triangle.right.y,
        triangle.center.x, triangle.center.y
    ])
    return coords


def TrianglesList_To_NumpyArray(triangle: List[Triangle]) -> np.array:
    result = np.zeros(shape=(0, 6))
    for T in triangle:
        result = np.vstack([result, Triangle2NumpyArray(T)])
    return result

def TransformTriangleNumpy(sample: np.array, coef: Coefficient) -> np.array:
    # Just multiply center.Y * coef.A
    return sample * [1, 1, 1, 1, 1, coef.A]

def MakePrediction(sample: np.array, coef: Coefficient) -> np.array:
    # Same as TransformTriangleNumpy
    return TransformTriangleNumpy(sample, coef)


if __name__ == '__main__':
    count = 400
    # coef = Coefficient(a=2)
    coef = Coefficient(a=3)

    right_triangles = GetSampleRightTriangles(count)
    x = TrianglesList_To_NumpyArray(right_triangles)
    y = TransformTriangleNumpy(x, coef)

    coef_predicted = Coefficient(a=np.random.randn())

    counter = 0
    epochs_min = 1000;
    learning_rate = 1e-6

    for t in range(100_000_00):
        # Compute difference between predicted values and the actual ones 'y'
        diff = MakePrediction(x, coef_predicted) - y
        loss = np.square(diff).sum()

        # TODO: if K = 4 - works best.! k = 2 - original value
        K = 2.0
        grad_y_pred = K * diff
        grad_a = grad_y_pred.sum()

        coef_predicted.A -= learning_rate * grad_a

        if 0 == t % 1000:
            print(t, loss)

        epochs_min = epochs_min - 1;
        counter = counter + 1
        if 0.01 > loss and 0 > epochs_min:
            break;


    print(f'Actual vales: [{coef.A}]')
    print(f'Predictions: [{coef_predicted.A}]')
    print(f'loss: [{loss}]')
    print(f'counter: [{counter}]')