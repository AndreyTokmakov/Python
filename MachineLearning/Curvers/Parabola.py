from functools import reduce
from typing import List

import math
import matplotlib.pyplot as plt
import numpy as np


# TODO: Params for parabola equation  [y = A * x*x + B * x + C]
class Coefficient(object):
    A = 0
    B = 0
    C = 0

    def __init__(self, a=0, b=0, c=0):
        self.A = a
        self.B = b
        self.C = c


def GetParabolaCoefsFromPoints(x: List, y: List):
    # points = getControlPoints(points)
    x1, x2, x3 = x[0], x[1], x[2]
    y1, y2, y3 = y[0], y[1], y[2]

    coef = Coefficient()
    coef.A = (y3 - (x3 * (y2 - y1) + x2 * y1 - x1 * y2) / (x2 - x1)) / (x3 * (x3 - x2 - x1) + x1 * x2)
    coef.B = (y2 - y1) / (x2 - x1) - coef.A * (x1 + x2)
    coef.C = (x2 * y1 - x1 * y2) / (x2 - x1) + coef.A * x1 * x2
    return coef


def equationParabola(x, coef: Coefficient):
    return coef.A * (x ** 2) + coef.B * x + coef.C


def DisplayParabola():
    count = 40
    coef = Coefficient(2, 3, 5)

    x = np.linspace(-count / 2, count / 2, count)
    y = equationParabola(x, coef)

    plt.scatter(x, y)
    plt.show()


if __name__ == '__main__':
    # DisplayParabola()

    x = [-10, 0, 10]
    y = [0,  20,  0]
    params = GetParabolaCoefsFromPoints(x, y)

    print(params.A, params.B, params.C)
