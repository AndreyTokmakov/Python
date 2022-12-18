import sys

import numpy as np
import math

# TODO: Params for parabola equation  [y = A * x*x + B * x + C]
class Coefficient(object):
    A = 0
    B = 0
    C = 0

    def __init__(self, a=0, b=0, c=0):
        self.A = a
        self.B = b
        self.C = c

def equationParabola(x, coef: Coefficient) -> int:
    return coef.A * (x ** 2) + coef.B * x + coef.C

def PredictTest():
    count = 50
    coef = Coefficient(2, 3, 5)
    x = np.linspace(-count/2, count/2, count)

    # TODO: Against overflow
    x = x / np.max(x)

    y = equationParabola(x, coef)



    # Randomly initialize weights
    coef_predicted = Coefficient()
    coef_predicted.A = np.random.randn()
    coef_predicted.B = np.random.randn()
    coef_predicted.C = np.random.randn()

    counter = 0
    epochs_min = 1000;
    learning_rate = 1e-6

    for t in range(100_000_00):
        # Forward pass: compute predicted Y value: y = a_new * x + b_new
        diff = equationParabola(x, coef_predicted) - y

        # Compute loss: Mean Squared Error
        # The sum of the squares of the difference between the assumed value and the actual
        loss = np.square(diff).sum()

        # if counter % 10000 == 0:
        #     print(counter, loss)

        # TODO: if K = 4 - works best.! k = 2 - original value
        K = 4.0
        grad_y_pred = K * diff

        grad_c = grad_y_pred .sum()
        grad_b = (grad_y_pred * x).sum()
        grad_a = (grad_y_pred * x * x).sum()

        # Update weights
        coef_predicted.A -= learning_rate * grad_a
        coef_predicted.B -= learning_rate * grad_b
        coef_predicted.C -= learning_rate * grad_c

        epochs_min = epochs_min - 1;
        if (0.01 > loss and 0 > epochs_min):
            break;
        counter = counter + 1


    print(f'Actual vales: [{coef.A}, {coef.B}, {coef.C}]')
    print(f'Predictions: [{coef_predicted.A}, {coef_predicted.B} {coef_predicted.C}]')
    print(f'loss: [{loss}]')
    print(f'counter: [{counter}]')


if __name__ == '__main__':
    PredictTest()