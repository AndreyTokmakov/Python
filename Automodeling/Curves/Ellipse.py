import functools
from typing import Tuple, List

import sys
import math
import numpy as np
from matplotlib import pyplot as plt
from collections.abc import Callable


class Utils(object):

    # Calculate the line Slope-Intercept equation coefficients 2D only
    @staticmethod
    def get_line_coefficients(pt1: List, pt2: List) -> Tuple[float, float]:
        # angular coefficient - tilt to the XS-axis
        slope = (pt2[1] - pt1[1]) / (pt2[0] - pt1[0])
        # straight line offset - the segment cut off from the axis
        intercept = (pt2[0] * pt1[1] - pt1[0] * pt2[1]) / (pt2[0] - pt1[0])
        return slope, intercept

    # Calculate angle between two 3D points
    @staticmethod
    def angle_between_vectors(vector1: np.ndarray,
                              vector2: np.ndarray) -> float:
        a = np.dot(vector1, vector2)
        b = np.sqrt(np.dot(vector1, vector1)) * np.sqrt(np.dot(vector2, vector2))
        return math.acos(a / b) * 180 / math.pi

    # Calculate distance between two 2D points
    @staticmethod
    def two_points_distance(pt1: List, pt2: List) -> float:
        return math.dist(pt1, pt2)

    # a --> X radius, b --> Y radius
    @staticmethod
    def equationEllipse(x: float, a: float, b: float) -> float:
        if x == a or 0 == a or 0 == b:
            return 0
        return math.sqrt((b * b) * (1 - (x * x) / (a * a)))


class Point2D(object):

    def __init__(self, x: float, y: float):
        self.x = x
        self.y = y

    def __repr__(self):
        return f'Point2D({self.x}, {self.y})'

    def __str__(self):
        return f'Point2D({self.x}, {self.y})'

    # Implements 'List like' behavior
    def __iter__(self):
        for elem in [self.x, self.y]:
            yield elem

    # Adding two Point2D:
    def __add__(self, other):
        return Point2D(self.x + other.x, self.y + other.y)

    # Minus:
    def __sub__(self, other):
        return Point2D(self.x - other.x, self.y - other.y)

    # Plus-Equals operator:
    def __iadd__(self, other):
        return self + other

    # Minus-Equals operator:
    def __isub__(self, other):
        return self - other

    def distanceTo(self, pt1) -> float:
        return math.dist([self.x, self.y], [pt1.x, pt1.y])


class Line2DSegment(object):

    def __init__(self, pt1: Point2D, pt2: Point2D):
        self.pt1 = pt1
        self.pt2 = pt2
        # self.dist: float = math.dist(pt1, pt2)

    def __repr__(self):
        return f'Line2DSegment({self.pt1}, {self.pt2})'

    def __str__(self):
        return f'Line2DSegment({self.pt1}, {self.pt2})'

    def midPoint(self) -> Point2D:
        return Point2D((self.pt1.x + self.pt2.x) / 2,
                       (self.pt1.y + self.pt2.y) / 2)

    def setCenter(self, center: Point2D):
        step = center - self.midPoint()
        self.pt1 += step
        self.pt2 += step

    def rotateAroundCenter(self, angle: float):
        angle = np.deg2rad(angle)
        sin, cos = math.sin(angle), math.cos(angle)
        center = self.midPoint()

        px, py = self.pt1
        self.pt1.x = center.x + cos * (px - center.x) - sin * (py - center.y)
        self.pt1.y = center.y + sin * (px - center.x) + cos * (py - center.y)

        px, py = self.pt2
        self.pt2.x = center.y + cos * (px - center.x) - sin * (py - center.y)
        self.pt2.y = center.y + sin * (px - center.x) + cos * (py - center.y)


class Tests(object):

    @staticmethod
    def simple_ellipse():
        xRadius, yRadius = 10, 14

        X = np.linspace(-10, 10, 100)
        Y = np.asarray([Utils.equationEllipse(v, xRadius, yRadius) for v in X])

        plt.plot(X, Y)
        plt.grid(color='lightgray', linestyle='--')

    @staticmethod
    def plotLineSegment(line: Line2DSegment, plotCenter: bool = False) -> None:
        plt.scatter([line.pt1.x, line.pt2.x], [line.pt1.y, line.pt2.y])
        plt.plot([line.pt1.x, line.pt2.x], [line.pt1.y, line.pt2.y])
        if plotCenter:
            center = line.midPoint()
            plt.scatter(center.x, center.y)

    @staticmethod
    def getLines() -> List[Line2DSegment]:
        return [
            Line2DSegment(Point2D(-10.5, 1.0), Point2D(-9.0, 4.0)),
            Line2DSegment(Point2D(-10.0, 4.0), Point2D(-8., 7.0)),
            Line2DSegment(Point2D(-8.5, 7.0), Point2D(-7.5, 10.0)),
            Line2DSegment(Point2D(-6.6, 10.0), Point2D(-5.0, 13.0)),
            Line2DSegment(Point2D(-4.3, 12.4), Point2D(-0.8, 14.5)),
            Line2DSegment(Point2D(-0.2, 14.5), Point2D(3.5, 12.5)),
            Line2DSegment(Point2D(3.7, 12.8), Point2D(6.9, 10.8)),
            Line2DSegment(Point2D(7.0, 10.4), Point2D(8.0, 7.0)),
            Line2DSegment(Point2D(8.4, 7.0), Point2D(10.0, 4.0)),
            Line2DSegment(Point2D(9.1, 4.0), Point2D(10.3, 1.0)),
        ]

    @staticmethod
    def PutLineOnTheCurve():
        xRadius, yRadius = 10, 14

        X = np.linspace(-10, 10, 100)
        Y = np.asarray([Utils.equationEllipse(v, xRadius, yRadius) for v in X])

        plt.plot(X, Y)
        plt.grid(color='lightgray', linestyle='--')

        segment = Line2DSegment(Point2D(-10.7, 1.0), Point2D(-8.2, 6.0))

        mid = segment.midPoint()
        plt.scatter(mid.x, mid.y)

        Tests.plotLineSegment(segment)

    # TODO: Need to optimize
    #       xStart , xEnd should depends of segment position
    @staticmethod
    def findClosestPoints(ptFrom: Point2D,
                          func: Callable,
                          xStart: float, xEnd: float) -> Point2D:
        dist_previous, ptClosest = sys.float_info.max, None
        for x in np.linspace(xStart, xEnd, num=100):
            p = Point2D(x, func(x))
            dist = ptFrom.distanceTo(p)
            if dist_previous > dist:
                dist_previous = dist
                ptClosest = p
            else:
                break
        return ptClosest

    @staticmethod
    def FindClosestPoint():
        xRadius, yRadius = 10, 14
        ellipse = functools.partial(Utils.equationEllipse, a=xRadius, b=yRadius)

        X = np.linspace(-xRadius, xRadius, 100)
        Y = np.asarray([ellipse(v) for v in X])

        plt.plot(X, Y)
        plt.grid(color='lightgray', linestyle='--')

        pt = Point2D(15.0, 13.5)
        closet = Tests.findClosestPoints(pt, ellipse, -xRadius, xRadius)

        plt.scatter(pt.x, pt.y)
        plt.scatter(closet.x, closet.y)

    @staticmethod
    def SetNewCenterForSegment():
        xRadius, yRadius = 10, 14
        ellipse = functools.partial(Utils.equationEllipse, a=xRadius, b=yRadius)

        X = np.linspace(-xRadius, xRadius, 100)
        Y = np.asarray([ellipse(v) for v in X])

        plt.plot(X, Y)
        plt.grid(color='lightgray', linestyle='--')

        line = Line2DSegment(Point2D(-8.5, 1.0), Point2D(-7.0, 4.0))

        # Plot old line:
        Tests.plotLineSegment(line, plotCenter=True)

        closet = Tests.findClosestPoints(line.midPoint(), ellipse, -xRadius, xRadius)
        line.setCenter(closet)

        Tests.plotLineSegment(line, plotCenter=True)
        plt.scatter(closet.x, closet.y)

    @staticmethod
    def RotateLineSegmentTest():
        xRadius, yRadius = 10, 14
        ellipse = functools.partial(Utils.equationEllipse, a=xRadius, b=yRadius)

        X = np.linspace(-xRadius, xRadius, 100)
        Y = np.asarray([ellipse(v) for v in X])

        plt.plot(X, Y)
        plt.grid(color='lightgray', linestyle='--')

        # line = Line2DSegment(Point2D(-8.5, 1.0), Point2D(-7.0, 4.0))
        line = Line2DSegment(Point2D(0, 0), Point2D(0.0, 5.0))
        Tests.plotLineSegment(line, plotCenter=False)
        print(line.pt1.distanceTo(line.pt2))

        line.rotateAroundCenter(90)
        Tests.plotLineSegment(line, plotCenter=False)
        print(line.pt1.distanceTo(line.pt2))


if __name__ == '__main__':
    '''
    Tests.simple_ellipse()

    lines: List[Line2DSegment] = Tests.getLines()
    for segment in lines:
        Tests.plotLineSegment(segment)
    '''

    # Tests.PutLineOnTheCurve()
    # Tests.FindClosestPoint()
    # Tests.SetNewCenterForSegment()
    # Tests.RotateLineSegmentTest()

    # plt.show()


    line = Line2DSegment(Point2D(0, -3.0), Point2D(0.0, 3.0))
    Tests.plotLineSegment(line, plotCenter=False)
    print(line.pt1.distanceTo(line.pt2))

    line.rotateAroundCenter(90)
    Tests.plotLineSegment(line, plotCenter=False)
    print(line.pt1.distanceTo(line.pt2))

    plt.show()


    '''
    def rotate(p, origin=(0, 0), degrees=0):
        angle = np.deg2rad(degrees)
        R = np.array([[np.cos(angle), -np.sin(angle)],
                      [np.sin(angle), np.cos(angle)]])
        o = np.atleast_2d(origin)
        p = np.atleast_2d(p)
        return np.squeeze((R @ (p.T - o.T) + o.T).T)
    '''
