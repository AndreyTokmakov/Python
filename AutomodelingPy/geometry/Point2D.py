import math


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

    # (*) operator
    def __mul__(self, v: float):
        return Point2D(self.x * v, self.y * v)

    # (*=) operator
    def __imul__(self, v: float):
        return Point2D(self.x * v, self.y * v)

    def distanceTo(self, pt1) -> float:
        return math.dist([self.x, self.y], [pt1.x, pt1.y])

    def clone(self):
        return Point2D(self.x, self.y)
