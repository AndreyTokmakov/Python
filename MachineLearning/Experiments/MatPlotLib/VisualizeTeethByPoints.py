from functools import reduce
from typing import List

import math
import matplotlib.pyplot as plt
import numpy as np

# TODO: 'sudo apt install python3-tk' is required

# TODO: Params for parabola equation  [y = A * x*x + B * x + C]
class Сoefficient(object):
    A = 0
    B = 0
    C = 0


def getPoints() -> List:
    points = [[5.0119, 23.5184, 8.45924],
              [12.1313, 20.9934, 8.44134],
              [16.3904, 16.7061, 8.23462],
              [18.7724, 9.23793, 8.83155],
              [23.4843, -7.35374, 9.52168],
              [-4.11237, 24.3166, 8.74011],
              [-11.03, 21.9617, 7.89354],
              [-16.0661, 18.1207, 8.08788],
              [-19.2935, 11.6917, 6.14457],
              [-2.09731, 22.3884, 0.927823],
              [-7.1348, 20.6635, 1.05399],
              [-11.7921, 17.252, 1.04259],
              [-16.6729, 11.8305, 1.01518],
              [-19.4861, 5.06582, 2.0793],
              [-23.6029, -8.17505, 5.1308],
              [2.79517, 22.2427, 1.0223],
              [8.04255, 20.5423, 1.23577],
              [12.1356, 17.0594, 1.20936],
              [16.77, 11.4449, 2.21954],
              [19.6428, 4.44371, 2.76032]]
    points.sort()
    return points


def getLowerPoints(points: List) -> List:
    y = [pt[2] for pt in points]
    y_avg = reduce(lambda x, y: x + y, y) / len(y)
    return [pt for pt in points if pt[2] < y_avg]


def getUpperPoints(points: List) -> List:
    y = [pt[2] for pt in points]
    y_avg = reduce(lambda x, y: x + y, y) / len(y)
    return [pt for pt in points if pt[2] > y_avg]


def getControlPoints(points: List) -> List:
    count = len(points);
    # Return first, middle and the last elements from he list
    return [points[0], points[int(count/2)], points[-1]]


def GetParabolaCoefsFromPoints(points):
    points = getControlPoints(points)
    x1 = points[0][0]
    y1 = points[0][1]
    x2 = points[1][0]
    y2 = points[1][1]
    x3 = points[2][0]
    y3 = points[2][1]

    coef = Сoefficient()
    coef.A = (y3 - (x3 * (y2 - y1) + x2*y1 - x1*y2) / (x2 - x1)) / (x3 * (x3 - x2 - x1) + x1 * x2)
    coef.B = (y2 - y1)/(x2 - x1) - coef.A * (x1 + x2)
    coef.C = (x2*y1 - x1*y2) / (x2 - x1) + coef.A * x1*x2
    return coef


def get_Y_from_X_and_Coefs(x, coef: Сoefficient):
    return coef.A * (x ** 2) + coef.B * (x) + coef.C


def DisplayPoints_FromTreatmentPlan():
    points = getPoints()
    points = getLowerPoints(points)
    # points = getControlPoints(points)

    x = [pt[0] for pt in points]
    z = [pt[1] for pt in points]

    plt.scatter(x, z)
    plt.show()


def DisplayPoints_FromTreatmentPlan_Coefs():
    points = getPoints()
    points = getLowerPoints(points)

    # TODO: Get A,B,C for [y = A * x*x + B * x + C]
    coefs = GetParabolaCoefsFromPoints(getControlPoints(points))

    x = [pt[0] for pt in points]
    z = [get_Y_from_X_and_Coefs(pt[0], coefs) for pt in points]

    plt.plot(x, z)
    plt.show()


if __name__ == '__main__':
    # DisplayPoints_FromTreatmentPlan()
    DisplayPoints_FromTreatmentPlan_Coefs()
