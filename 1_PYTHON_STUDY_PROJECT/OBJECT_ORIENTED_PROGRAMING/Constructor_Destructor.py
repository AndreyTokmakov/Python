'''
Created on Nov 26, 2020
@author: AndTokm
'''


class Point(object):

    def __init__(self, x=0, y=0):
        self.__x = x
        self.__y = y
        print("Creating Point({0}, {1})".format(self.__x, self.__y));

    def __del__(self):
        print("Destructing Point({0}, {1})".format(self.__x, self.__y));


if __name__ == '__main__':
    p = Point()
    p1 = Point(1, 3)
