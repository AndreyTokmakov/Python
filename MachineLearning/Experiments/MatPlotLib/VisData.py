from functools import reduce
from typing import List

import math
import matplotlib.pyplot as plt
import numpy as np

# TODO: 'sudo apt install python3-tk' is required

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
    return points

def getLowerPoints(points: List) -> List:
    y = [pt[2] for pt in points]
    y_avg = reduce(lambda x, y: x + y, y) / len(y)

    return  [pt[0] for pt in points if pt[2] < y_avg]

def DisplayPointsRandom():
    print("Running tests.")
    x = np.random.rand(100)
    y = np.sin(x) * np.power(x, 3) + 3 * x + np.random.rand(100) * 0.8

    plt.scatter(x, y)
    plt.show()


def DisplayPoints_FromTreatmentPlan():
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



    y = [pt[2] for pt in points]
    y_avg = reduce(lambda x, y: x + y, y) / len(y)

    x = [pt[0] for pt in points if pt[2] < y_avg]
    z = [pt[1] for pt in points if pt[2] < y_avg]
    print (x)
    print (z)

    plt.scatter(x, z)
    plt.show()


def DrawParabola():
    # create 1000 equally spaced points between -10 and 10
    x = np.linspace(-10, 10, 1000)

    # calculate the y value for each element of the x vector
    y = x ** 2 + 2 * x + 2

    fig, ax = plt.subplots()
    ax.plot(x, y)
    plt.show()


def DrawParabola2():
    x_cords = range(-50, 50)
    y_cords = [x * x for x in x_cords]

    plt.scatter(x_cords, y_cords)
    plt.show()

def DrawParabola_FromPointsTest():
    coef = GetParabolaCoefsFromPoints([[-19.4861, 5.06582], [2.79517, 22.2427], [19.6428, 4.44371]])

    x = np.linspace(-10, 10, 1000)
    # calculate the y value for each element of the x vector
    y = coef[0] * x ** 2 + coef[1] * 2 * x + coef[2]

    fig, ax = plt.subplots()
    ax.plot(x, y)
    plt.show()

def GetParabolaCoefsFromPoints(points):
    x1 = points[0][0]
    y1 = points[0][1]
    x2 = points[1][0]
    y2 = points[1][1]
    x3 = points[2][0]
    y3 = points[2][1]

    a = (y3 - (x3 * (y2 - y1) + x2*y1 - x1*y2) / (x2 - x1)) / (x3 * (x3 - x2 - x1) + x1 * x2);
    b = (y2 - y1)/(x2 - x1) - a * (x1 + x2)
    c = (x2*y1 - x1*y2) / (x2 - x1) + a*x1*x2

    return [a, b, c]


if __name__ == '__main__':
    # DrawParabola();
    # DrawParabola2()
    DrawParabola_FromPointsTest();

    # DisplayPointsRandom()
    # DisplayPoints_FromTreatmentPlan()
