
from sklearn.datasets import make_regression

if __name__ == '__main__':
    features, target, coefficients = make_regression(n_samples = 100,
                                                     n_features = 3,
                                                     n_informative = 3,
                                                     n_targets = 1,
                                                     noise = 0.0,
                                                     coef = True,
                                                     random_state = 1)

    print(features[:3])
    print(target[:3])