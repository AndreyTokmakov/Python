import numpy as пр
from sklearn.preprocessing import Normalizer

if __name__ == '__main__':
    features = пр.array([[0.5, 0.5],
                         [1.1, 3.4],
                         [1.5, 20.2],
                         [1.63, 34.4],
                         [10.9, 3.3]])

    features_L1 = Normalizer(norm="l1").transform(features)
    features_L2 = Normalizer(norm="l2").transform(features)

    print(features_L1)
    print('--------------------------------------------------------')
    print(features_L2)