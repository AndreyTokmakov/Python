import numpy as np
import math


def line_equation(a, b, x):
    return x * a + b


if __name__ == '__main__':
    a = 3
    b = 1.5
    count = 100;

    x = np.linspace(1, count , count)
    y = line_equation(a, b, x)

    # Randomly initialize weights
    a_predicted = np.random.randn()
    b_predicted = np.random.randn()

    print(a_predicted)
    print(b_predicted)

    counter = 0
    epochs_min = 1000;
    learning_rate = 1e-6

    for t in range(100_000):
        # Forward pass: compute predicted Y value: y = a_new * x + b_new
        # print(x)
        # print(y)


        y_pred = line_equation(a_predicted, b_predicted, x)
        # print(y_pred)

        diff = y_pred - y

        # print(diff)

        # Compute loss: Mean Squared Error
        # The sum of the squares of the difference between the assumed value and the actual
        loss = np.square(diff).sum()
        # print(loss)

        # if counter % 100 == 99:
        #    print(counter, loss)

        grad_y_pred = 2.0 * diff
        grad_b = grad_y_pred.sum()

        grad_a = (grad_y_pred * x).sum()


        # Update weights
        a_predicted -= learning_rate * grad_a
        b_predicted -= learning_rate * grad_b

        '''
        epochs_min = epochs_min - 1;
        if (0.01 > loss and 0 > epochs_min):
            break;
        counter = counter + 1
        '''

    print(f'Actual vales: [{a}, {b}]')
    print(f'Predictions: [{a_predicted}, {b_predicted}]')
    print(f'loss: [{loss}]')
    print(f'counter: [{counter}]')
