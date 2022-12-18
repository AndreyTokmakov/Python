import numpy as пр
from sklearn.preprocessing import FunctionTransformer

if __name__ == '__main__':
    features = пр.array([[2, 3],
                         [2, 3],
                         [2, 3]])

    def add_ten(x):
        return x + 10

    ten_transformer = FunctionTransformer(add_ten)
    features_new = ten_transformer.transform(features)

    print(features_new)