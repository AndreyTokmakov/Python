
import random
import numpy as np
import matplotlib.pyplot as plt


def get_points(num: int = 10,
               noise: float = 0.1):
    a, b = 1.0, 2.0
    x_points: np.ndarray = np.linspace(0.0, float(num) - 1, num)
    y_points: np.ndarray = np.zeros(np.size(x_points), float)

    noise_range: float = (a * num + b) * noise
    for i in range(np.size(x_points)):
        y_points[i] = a * x_points[i] + b
        y_points[i] += random.uniform(-noise_range, noise_range)
        i += 1

    return x_points, y_points


if __name__ == '__main__':
    x, y = get_points(40)

    A = np.vstack([x, np.ones(len(x))]).T
    print(A)

    m, c = np.linalg.lstsq(A, y, rcond=None)[0]
    print(m, c)

    plt.plot(x, y, 'o', label='Original data', markersize=4)
    plt.plot(x, m*x + c, 'r', label='Fitted line')
    plt.legend()
    plt.show()