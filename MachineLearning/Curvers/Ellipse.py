import numpy as np
from matplotlib import pyplot as plt
from math import pi

# x_pos = x + a * cos(t)
# y_pos = y + b * sin(t)
def simple_ellipse():
    x, y = 3.0, 0.5   # x, y position of the center
    a = 2.0   # radius on the x-axis
    b = 0.1   # radius on the y-axis

    t = np.linspace(0, 2 * pi, 100)
    plt.plot(x + a * np.cos(t), y + b * np.sin(t))
    plt.grid(color='lightgray', linestyle='--')
    plt.show()


if __name__ == '__main__':
    # simple_ellipse()

    pt1: np.ndarray = np.asarray([-25.5461, -3.96054])
    pt2: np.ndarray = np.asarray([-20.9445, 13.5125])
    center: np.ndarray = np.asarray([0.0308352, 25.693])
    pt3: np.ndarray = np.asarray([22.1581, 14.1476])
    pt4: np.ndarray = np.asarray([28.2013, -3.13935])


    x: np.ndarray = np.asarray([pt1[0], pt2[0], center[0], pt3[0], pt4[0]])
    y: np.ndarray = np.asarray([pt1[1], pt2[1], center[1], pt3[1], pt4[1]])



    c: np.ndarray = (pt1 + pt4) / 2
    a: float = (pt1[0] - pt4[0])/2  # radius on the x-axis
    b: float = pt1[1] - center[1]   # radius on the y-axis


    t = np.linspace(0, 2 * pi, 100)

    plt.scatter(x, y)
    plt.plot(c[0] + a * np.cos(t), c[1] + b * np.sin(t))
    plt.grid(color='lightgray', linestyle='--')
    plt.show()

