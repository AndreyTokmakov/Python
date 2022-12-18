import numpy as np
import math

# Equation of the line:
# xArg - X value (independent variable)
# A = slope, B - intercept
def func(xArg: float, A: float, B: float) -> float:
    return xArg * A + B


if __name__ == '__main__':
    a, b = 3, 1.5   # Input coefficients A and B
    count: int = 100

    # Generate points (aka original data X and Y)
    x = np.linspace(0, count, count)
    y = func(x, a, b)

    # Randomly initialize weights
    a_pred = np.random.randn()
    b_pred = np.random.randn()

    iterations, epochs_min = 0, 1000
    learning_rate = 1e-6
    while True:
        # Forward pass: compute predicted Y value: y = a_new * x + b_new
        y_pred = func(x, a_pred, b_pred)

        # Compute loss
        loss = np.square(y_pred - y).sum()
        # if counter % 100 == 99:
        #    print(counter, loss)

        grad_y_pred = 2.0 * (y_pred - y)

        grad_a = (grad_y_pred * x).sum()
        grad_b = grad_y_pred.sum()

        # Update weights
        a_pred -= learning_rate * grad_a
        b_pred -= learning_rate * grad_b

        epochs_min = epochs_min - 1;
        if 0.01 > loss and 0 > epochs_min:
            break
        iterations += 1

    print(f'Actual vales: [{a}, {b}]')
    print(f'Predictions: [{a_pred}, {b_pred}]')
    print(f'Iterations count: [{iterations}], Loss: [{loss}]')
