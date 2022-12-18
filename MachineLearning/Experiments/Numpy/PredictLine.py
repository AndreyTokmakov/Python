import numpy as np
import math

if __name__ == '__main__':
    a = 3
    b = 1.5
    count = 100;
    equation = lambda x: x * a + b

    x = np.linspace(0, count, count)
    y = equation(x)

    # Randomly initialize weights
    a_predicted = np.random.randn()
    b_predicted = np.random.randn()

    counter = 0
    epochs_min = 1000;
    learning_rate = 1e-6
    # for t in range(5000):
    while (True):
        # Forward pass: compute predicted Y value: y = a_new * x + b_new
        y_pred = a_predicted * x + b_predicted

        # Compute loss
        loss = np.square(y_pred - y).sum()
        # if counter % 100 == 99:
        #    print(counter, loss)

        grad_y_pred = 2.0 * (y_pred - y)

        grad_a = (grad_y_pred * x).sum()
        grad_b = grad_y_pred.sum()

        # Update weights
        a_predicted -= learning_rate * grad_a
        b_predicted -= learning_rate * grad_b

        epochs_min = epochs_min - 1;
        if (0.05 > loss and 0 > epochs_min):
            break;
        counter = counter + 1

    print(f'Actual vales: [{a}, {b}]')
    print(f'Predictions: [{a_predicted}, {b_predicted}]')
    print(f'loss: [{loss}]')
    print(f'counter: [{counter}]')