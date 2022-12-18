import random

import matplotlib.pyplot as plt
import numpy as np


# Equation of the line:
# xArg - X value (independent variable)
# A = slope, B - intercept
def equation(X, A: float, B: float):
    return X * A + B


# Mean Squared Error function, or L2 loss.
def calculate_loss(X, Y, weight, bias):
    size, error = len(X), 0.0
    for i in range(size):
        error += (Y[i] - (weight * X[i] + bias)) ** 2
    return error / size


# To solve for the gradient, we iterate through our data points using our new weight
# and bias values and take the average of the partial derivatives. The resulting gradient
# tells us the slope of our cost function at our current position (i.e. weight and bias)
# and the direction we should update to reduce our cost function (we move in the direction
# opposite the gradient). The size of our update is controlled by the learning rate.
def update_coefficients(X, Y, weight, bias, learning_rate):
    wDerivative, bDerivative = 0, 0
    size = len(X)

    for i in range(size):  # Calculate partial derivatives
        # -2x(y - (mx + b))
        wDerivative += -2 * X[i] * (Y[i] - equation(X[i], weight, bias))
        # -2(y - (mx + b))
        bDerivative += -2 * (Y[i] - equation(X[i], weight, bias))

    # We subtract because the derivatives point in direction of steepest ascent
    weight -= (wDerivative / size) * learning_rate
    bias -= (bDerivative / size) * learning_rate

    return weight, bias


def train(X, Y, weight, bias, learning_rate, iterations):
    # cost_history = []

    for i in range(iterations):
        weight, bias = update_coefficients(X, Y, weight, bias, learning_rate)

        # Calculate cost for auditing purposes
        loss = calculate_loss(X, Y, weight, bias)
        # cost_history.append(loss)

        # Log Progress
        #if i % 10 == 0:
        #     print(f'iterations: {i} weight: {weight} bias: {bias} cost: {loss}')

    return weight, bias


def get_data(size: int, A: float, B: float):
    x: np.ndarray = np.linspace(1, size, size)
    y: np.ndarray = equation(x, A, B)
    solt: np.ndarray = np.array([random.randint(-15000, 15000) / 100000 + 1 for i in range(size)])
    return x, y * solt

# TODO: Bad results
# TODO: b_pred predicted really wrong
if __name__ == '__main__':
    a, b = 3.5, 7.8
    x, y = get_data(200, a, b)

    iterations, learning_rate = 10_000, 1e-8
    a_pred, b_pred = np.random.randn(), np.random.randn()

    a_pred, b_pred = train(x, y, a_pred, b_pred, learning_rate, iterations)

    print(f'Originals: weight = {a}, bias = {b}')
    print(f'Predicted: weight = {a_pred}, bias = {b_pred}')

    y_p = np.asarray([equation(v, a_pred, b_pred) for v in x])

    plt.plot(x, y, color="g")
    plt.plot(x, y_p, color="r")
    plt.show()
