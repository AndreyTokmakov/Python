import numpy as np
import pandas as pd
import matplotlib.pyplot as plt

if __name__ == '__main__':
    students = {'hours': [29, 9, 10, 38, 16, 26, 50, 10, 30, 33, 43, 2, 39, 15, 44, 29, 41, 15, 24, 50],
                'test_results': [65, 7, 8, 76, 23, 56, 100, 3, 74, 48, 73, 0, 62, 37, 74, 40, 90, 42, 58, 100]}

    student_data = pd.DataFrame(data=students)
    x = student_data.hours
    y = student_data.test_results

    model = np.polyfit(x, y, 1)
    predict = np.poly1d(model)

    # sets the range you want to display the linear regression model over —  between 0 and 50 hours.
    x_lin_reg = range(0, 51)

    #  calculates the y values for all the x values between 0 and 50
    y_lin_reg = predict(x_lin_reg)

    # plots your original dataset on a scatter plot.
    plt.scatter(x, y)

    # prints the linear regression model — based on the x_lin_reg and y_lin_reg
    plt.plot(x_lin_reg, y_lin_reg, c='r')
    plt.show()
