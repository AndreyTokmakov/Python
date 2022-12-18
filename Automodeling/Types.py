import math


class Point2D(object):
    def __init__(self, coord_x, coord_y):
        self.x = coord_x
        self.y = coord_y

    def shift(self, x, y):
        self.x += x
        self.y += y

    def __str__(self):
        return f'({self.x} , {self.y})'

    def __add__(self, other):
        """Point(x1+x2, y1+y2)"""
        return Point2D(self.x + other.x, self.y + other.y)

    def __sub__(self, other):
        """Point(x1-x2, y1-y2)"""
        return Point2D(self.x - other.x, self.y - other.y)

    def __mul__(self, scalar):
        """Point(x1*x2, y1*y2)"""
        return Point2D(self.x * scalar, self.y * scalar)

    def __div__(self, scalar):
        """Point(x1/x2, y1/y2)"""
        return Point2D(self.x / scalar, self.y / scalar)

    def __str__(self):
        return "(%s, %s)" % (self.x, self.y)

    def __repr__(self):
        return "%s(%r, %r)" % (self.__class__.__name__, self.x, self.y)

    def distance_to(self, other):
        return math.hypot(self.x - other.x, self.y - other.y)

    def dot(self, other):
        return self.x * other.x + self.y * other.y

    @staticmethod
    def dot(pt1, pt2):
        return pt1.x * pt2.x + pt1.y * pt2.y

    def as_tuple(self):
        """(x, y)"""
        return (self.x, self.y)

    def clone(self):
        """"Return a full copy of this point."""
        return Point2D(self.x, self.y)

    def rotate(self, rad):
        """  Rotate counter-clockwise by rad radians.
        Positive y goes *up,* as in traditional mathematics. Interestingly, you
        can use this in y-down computer graphics, if you just remember that it
        turns clockwise, rather than counter-clockwise.
        The new position is returned as a new Point.
        """
        s, c = [f(rad) for f in (math.sin, math.cos)]
        x, y = (c * self.x - s * self.y, s * self.x + c * self.y)
        return Point2D(x, y)

    def rotate_about(self, p, theta):
        """ Rotate counter-clockwise around a point, by theta degrees.
        Positive y goes *up,* as in traditional mathematics.
        The new position is returned as a new Point.
        """
        result = self.clone()
        result.slide(-p.x, -p.y)
        result.rotate(theta)
        result.slide(p.x, p.y)
        return result


class Point3D(object):
    def __init__(self, coord_x, coord_y, coord_z):
        self.x = coord_x
        self.y = coord_y
        self.z = coord_z

    def shift(self, x, y, z):
        self.x += x
        self.y += y
        self.z += z

    def __repr__(self):
        return "".join(["Point3D(", str(self.x), ",", str(self.y), ",", str(self.z), ")"])

    def __str__(self):
        return f'({self.x}, {self.y}, {self.z})'

    def __add__(self, other):
        """ Point3D(x1+x2, y1+y2, z1+z2) """
        return Point3D(self.x + other.x, self.y + other.y, self.z + other.z)

    def __sub__(self, other):
        """Point3D(x1-x2, y1-y2, z1-z2)"""
        return Point3D(self.x - other.x, self.y - other.y, self.z - other.z)

    def __mul__(self, scalar):
        """ Point3D(x1*x2, y1*y2, z1*z2) """
        return Point3D(self.x * scalar, self.y * scalar, self.z * scalar)

    def __div__(self, scalar):
        """ Point3D(x1/x2, y1/y2, z1/z2) """
        return Point3D(self.x / scalar, self.y / scalar, self.z / scalar)

    def distance_to(self, other):
        return math.hypot(self.x - other.x, self.y - other.y, self.z - other.z)

    def dot(self, other):
        return self.x * other.x + self.y * other.y + self.z * other.z

    def as_tuple(self):
        """ (x, y, z) """
        return self.x, self.y, self.z

    @staticmethod
    def dot(pt1, pt2):
        return pt1.x * pt2.x + pt1.y * pt2.y + pt1.z * pt2.z



class Line3D(object):
    def __init__(self, pt1: Point3D, pt2: Point3D):
        self.pt1: Point3D = pt1
        self.pt2: Point3D = pt2

'''
if __name__ == '__main__':
    pt = Point2D(1.545, 3.3434)
    print(pt)
'''
