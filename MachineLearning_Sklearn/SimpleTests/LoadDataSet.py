
from sklearn import datasets

if __name__ == '__main__':
    digits = datasets.load_digits()
    features = digits.data
    target = digits.target
    print(features[0])
