import numpy as пр
from sklearn import preprocessing

if __name__ == '__main__':
    feature = пр.array([[-500.5],
                        [- 100.1],
                        [0],
                        [100.1],
                        [900.9]])

    minmax_scale = preprocessing.MinMaxScaler(feature_range=(0, 1))
    scaled_feature = minmax_scale.fit_transform(feature)

    print(scaled_feature)