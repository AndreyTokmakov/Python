
import numpy as np
import matplotlib.pyplot as plt

def Test0():
    x = np.arange(0, 30, 3)
    y = x**2

    p = np.polyfit(x, y, 2)  # Last argument is degree of polynomial
    predict = np.poly1d(p)

    x_test = 15
    y_pred = predict(x_test)

    plt.scatter(x, y)
    plt.xlabel("X-values")
    plt.ylabel("Y-values")
    plt.plot(x, y)
    plt.show()


def Test1():
    x = [10, 30, 50, 80, 100]
    y = [30, 45, 40, 20,  40]

    for x1, y1 in zip(x, y):
        plt.plot(x1, y1, 'ro')

    z = np.polyfit(x, y, 3)
    f = np.poly1d(z)

    for x1 in np.linspace(0, 110, 110):
        plt.plot(x1, f(x1), 'b+')

    plt.axis([0, 110, 0, 60])
    plt.show()

def Test2():
    x: np.ndarray = np.asarray([-25.5461, -20.9445, 0.0308352, 22.1581, 28.2013])
    y: np.ndarray = np.asarray([-3.96054, 13.5125, 25.693, 14.1476, -3.13935])

    for x1, y1 in zip(x, y):
        plt.plot(x1, y1, 'ro')

    z = np.polyfit(x, y, 3)
    f = np.poly1d(z)

    for x1 in np.linspace(-30, 33, 61):
        plt.plot(x1, f(x1), 'b+')

    plt.axis([-40, 40, -40, 40])
    plt.show()


def Test3():
    points = np.array([(1, 1), (2, 4), (3, 1), (9, 3)])

    x = points[:,0]
    y = points[:,1]

    # calculate polynomial
    z = np.polyfit(x, y, 2)
    f = np.poly1d(z)

    x_fit = np.linspace(-100, 100, 1000)
    y_fit = [f(_x) for _x in x_fit]

    plt.plot(x, y)
    plt.plot(x_fit, y_fit)
    plt.show()


if __name__ == '__main__':
    # Test0()
    # Test1()
    Test2()
    # Test3()

    pass