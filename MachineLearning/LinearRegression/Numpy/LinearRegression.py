import random

import numpy as np
import matplotlib.pyplot as plt


def estimate_coef(x, y):
    # number of observations/points
    n = np.size(x)
    # mean of x and y vector
    xMean, yMean = np.mean(x), np.mean(y)

    # calculating cross-deviation and deviation about x
    SS_xy = np.sum(y * x) - n * yMean * xMean
    SS_xx = np.sum(x * x) - n * xMean * xMean

    # calculating regression coefficients
    slope = SS_xy / SS_xx
    intercept = yMean - slope * xMean

    return slope, intercept


def plot_regression_line(x, y, slope, intercept):
    # plotting the actual points as scatter plot
    plt.scatter(x, y, color="m", marker="o", s=30)

    # predicted response vector
    y_pred = slope * x + intercept

    # plotting the regression line
    plt.plot(x, y_pred, color="g")

    # putting labels
    plt.xlabel('x')
    plt.ylabel('y')

    # function to show plot
    plt.show()


def get_data(size: int, A: float, B: float):
    x: np.ndarray = np.linspace(1, size, size)
    y: np.ndarray = x * A + B
    solt: np.ndarray = np.array([random.randint(-15000, 15000) / 100000 + 1 for i in range(size)])
    return x, y * solt


if __name__ == "__main__":
    # x = np.array([0, 1, 2, 3, 4, 5, 6, 7, 8, 9])
    # y = np.array([1, 3, 2, 5, 7, 8, 8, 9, 10, 12])

    a, b = 2.3, 5
    X, Y = get_data(200, a, b)

    # estimating coefficients
    a_pred, b_pred = estimate_coef(X, Y)
    print(f'Originals: weight = {a}, bias = {b}')
    print(f'Predicted: weight = {a_pred}, bias = {b_pred}')

    # plotting regression line
    plot_regression_line(X, Y, a_pred, b_pred)
