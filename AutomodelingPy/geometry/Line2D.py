import math
import numpy as np

from AutomodelingPy.geometry.Point2D import Point2D


class Line2D(object):

    def __init__(self, pt1: Point2D, pt2: Point2D):
        self.pt1 = pt1
        self.pt2 = pt2

    def __repr__(self):
        return f'Line2D({self.pt1}, {self.pt2})'

    def __str__(self):
        return f'Line2D({self.pt1}, {self.pt2})'

    def __rotate_around_point(self,
                              angle: float,
                              origin_point: Point2D) -> None:
        angle = np.deg2rad(angle)
        sin, cos = math.sin(angle), math.cos(angle)
        pt1, pt2, origin = self.pt1.clone(), self.pt2.clone(), origin_point.clone()
        self.pt1 = Point2D(origin.x + cos * (pt1.x - origin.x) - sin * (pt1.y - origin.y),
                           origin.y + sin * (pt1.x - origin.x) + cos * (pt1.y - origin.y))
        self.pt2 = Point2D(origin.x + cos * (pt2.x - origin.x) - sin * (pt2.y - origin.y),
                           origin.y + sin * (pt2.x - origin.x) + cos * (pt2.y - origin.y))

    def getMidPoint(self) -> Point2D:
        return Point2D((self.pt1.x + self.pt2.x) / 2,
                       (self.pt1.y + self.pt2.y) / 2)

    def setCenter(self, center: Point2D) -> None:
        step = center - self.getMidPoint()
        self.pt1 += step
        self.pt2 += step

    def getLength(self) -> float:
        return self.pt2.distanceTo(self.pt1)

    # TODO: Refactor
    def setPoint1(self, dest: Point2D) -> None:
        self.pt2 += dest - self.pt1
        self.pt1 = dest

    # TODO: Refactor
    def setPoint2(self, dest: Point2D) -> None:
        self.pt1 += dest - self.pt2
        self.pt2 = dest

    # TODO: Refactor
    def rotateAroundCenter(self, angle: float) -> None:
        self.__rotate_around_point(angle, self.getMidPoint())

    # TODO: Refactor
    def rotateAroundPoint1(self, angle: float) -> None:
        self.__rotate_around_point(angle, self.pt1)

    # TODO: Refactor
    def rotateAroundPoint2(self, angle: float) -> None:
        self.__rotate_around_point(angle, self.pt2)

    def swapPoints(self) -> None:
        self.pt1, self.pt2 = self.pt2, self.pt1

    def getDistanceBetweenCenters(self, line) -> float:
        return self.getMidPoint().distanceTo(line.getMidPoint())

    def clone(self):
        return Line2D(self.pt1.clone(), self.pt2.clone())

    # Sum Line2D + Point2D
    def __add__(self, other: Point2D):
        return Line2D(self.pt1 + other, self.pt2 + other)

    #  Sum Line2D - Point2D
    def __sub__(self, other):
        return Line2D(self.pt1 - other, self.pt2 - other)

    # Sum Line2D += Point2D
    def __iadd__(self, other: Point2D):
        return Line2D(self.pt1 + other, self.pt2 + other)

    # Sum Line2D -= Point2D
    def __isub__(self, other: Point2D):
        return Line2D(self.pt1 - other, self.pt2 - other)



    # TODO: getLineCoefficients(const Line2D& line)
    # TODO: getLineCoefficients(const Point2D& pt1, const Point2D& pt2)