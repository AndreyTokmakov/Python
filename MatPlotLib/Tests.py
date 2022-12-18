import math
from csv import DictReader

import matplotlib.pyplot as plt
import numpy as np

from functools import reduce
from typing import List


def DrawLine():
    a = 21
    b = 2

    x = [1, 2, 3, 4, 5]
    y = [(v * a + b) for v in x]

    plt.scatter(x, y)
    plt.show()


def DrawLine2():
    x = [7, 14, 21, 28, 35, 42, 49]
    y = [8, 13, 21, 30, 31, 44, 50]

    # Plot a simple line chart without any feature
    plt.plot(x, y)
    plt.show()



def plot_CSV():
    x, y, y_pred = [], [], []
    with open("S:\\Projects\\TEST_DATA\\CSV\\ml.csv", 'r') as read_obj:
        csv_dict_reader = DictReader(read_obj)
        for row in csv_dict_reader:
            x.append(float(row['x']))
            y.append(float(row['y']))
            y_pred.append(float(row['y_pred']))

    # plotting the actual points as scatter plot
    plt.scatter(x, y, color="m", marker="o", s=30)
    plt.plot(x, y_pred, color="g")

    # putting labels
    plt.xlabel('x')
    plt.ylabel('y')

    # function to show plot
    plt.show()


def DrawTwoGraphs():
    x = np.random.randint(low=1, high=11, size=50)
    y = x + np.random.randint(1, 5, size=x.size)
    data = np.column_stack((x, y))

    fig, (ax1, ax2) = plt.subplots(
        nrows=1, ncols=2,
        figsize=(8, 4)
    )

    ax1.scatter(x=x, y=y, marker='o', c='r', edgecolor='b')
    ax1.set_title('Scatter: $x$ versus $y$')
    ax1.set_xlabel('$x$')
    ax1.set_ylabel('$y$')

    ax2.hist(
        data, bins=np.arange(data.min(), data.max()),
        label=('x', 'y')
    )

    ax2.legend(loc=(0.65, 0.8))
    ax2.set_title('Frequencies of $x$ and $y$')
    ax2.yaxis.tick_right()

    plt.show()


if __name__ == '__main__':
    # DrawLine()
    # DrawLine2()
    plot_CSV()
    # Test2()