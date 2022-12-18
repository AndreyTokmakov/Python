import matplotlib.pyplot as plt
import numpy as np
import pandas as pd


def plot_regression_line(x, y, z):
    # plotting the actual points as scatter plot
    plt.scatter(x, y, color="m", marker="o", s=30)

    # plotting the regression line
    plt.plot(x, z, color="g")

    # putting labels
    plt.xlabel('x')
    plt.ylabel('y')

    # function to show plot
    plt.show()



if __name__ == '__main__':
    # DisplayPointsRandom()

    file = "/home/andtokm/tmp/data.csv"
    data_frame = pd.read_csv(file)

    x, y, z = data_frame['x'], data_frame['y'], data_frame['y_pred']

    plot_regression_line(x, y, z)

    pass
