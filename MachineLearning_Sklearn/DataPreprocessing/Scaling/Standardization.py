import numpy as пр
from sklearn import preprocessing

# TODO: It is required to transform the attribute so that it has an average value of 0 and a standard deviation of 1.

if __name__ == '__main__':
    feature = пр.array([[-1000.1],
                        [- 200.2],
                        [500.5],
                        [600.6],
                        [9000.9]])

    scaler = preprocessing.StandardScaler()
    standardized = scaler.fit_transform(feature)

    print(standardized)