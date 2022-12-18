class Point(object):

    def __init__(self, coord_x, coord_y):
        self.x = coord_x
        self.y = coord_y

    def __repr__(self):
        return f'Point({self.x}, {self.y})'


class Point3D(Point):

    def __init__(self, coord_x, coord_y, coord_z):
        super().__init__(coord_x, coord_y)
        self.z = coord_z

    def __repr__(self):
        return f'Point3D({self.x}, {self.y}, {self.z})'


