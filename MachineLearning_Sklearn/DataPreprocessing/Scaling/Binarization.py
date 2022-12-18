import numpy as np
from sklearn.preprocessing import Binarizer


def Binary_Transform():
    features = [[1., -1., 2.],
                [2., 0., 0.],
                [0., 1., -1.]]
    transformer = Binarizer().fit(features)  # fit does nothing.
    features_new = transformer.transform(features)

    print(features_new)


def Digitize():
    age = np.array([[6],
                    [12],
                    [20],
                    [36],
                    [65]])
    
    # Distribute the attribute to the baskets
    X = np.digitize(age, bins=[20, 30, 64])
    print(X)


if __name__ == '__main__':
    # Binary_Transform()
    Digitize()
