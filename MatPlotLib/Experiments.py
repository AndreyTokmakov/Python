import numpy as np
import matplotlib.pyplot as plt


def pcolormesh():
    # TODO: https://matplotlib.org/stable/plot_types/arrays/pcolormesh.html
    x = [-3, -2, -1.6, -1.2, -.8, -.5, -.2, .1, .3, .5, .8, 1.1, 1.5, 1.9, 2.3, 3]
    X, Y = np.meshgrid(x, np.linspace(-3, 3, 128))
    Z = (1 - X/2 + X**5 + Y**3) * np.exp(-X**2 - Y**2)


    fig, ax = plt.subplots()
    ax.pcolormesh(X, Y, Z, vmin=-0.5, vmax=1.0)
    plt.show()



def pcolormesh():
    # TODO: https://matplotlib.org/stable/plot_types/arrays/contour.html
    X, Y = np.meshgrid(np.linspace(-3, 3, 256), np.linspace(-3, 3, 256))
    Z = (1 - X/2 + X**5 + Y**3) * np.exp(-X**2 - Y**2)
    levels = np.linspace(np.min(Z), np.max(Z), 7)

    # plot
    fig, ax = plt.subplots()

    ax.contour(X, Y, Z, levels=levels)

    plt.show()


if __name__ == '__main__':
    # pcolormesh()
    pcolormesh()
