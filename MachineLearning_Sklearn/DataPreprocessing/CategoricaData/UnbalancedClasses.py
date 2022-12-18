
import numpy as np
from sklearn.ensemble import RandomForestClassifier
from sklearn.datasets import load_iris

if __name__ == '__main__':

    # Download the data of Iris Fischer flowers
    # The Fischer iris dataset contains three balanced classes of 50 observations,
    # each of which indicates the type of flower - iris bristly (Iris setosa),
    # iris virginica and iris multicolored (Iris versicolor).
    iris = load_iris()

    # Create a feature matrix
    features = iris.data

    # Create a vector of goals
    target = iris.target

    # Delete the first 40 observations
    features = features[40:,:]
    target = target[40:]

    # Create a binary vector of targets indicating whether the class is 0
    target = np.where((target == 0), 0, 1)

    # Take a look at the unbalanced vector of goals
    print(target)

    weights = {0: .9, 1: 0.1}

    RandomForestClassifier(class_weight=weights)
    RandomForestClassifier(bootstrap=True, class_weight={0: 0.9, 1: 0.1},
                           criterion='gini', max_depth=None,
                           max_features='auto',
                           max_leaf_nodes=None, min_impurity_decrease=0.0,
                           min_impurity_split=None, min_samples_leaf=l,
                           min_samples_split=2, min_weight_fraction_leaf=0.0,
                           n_estimators=10, n_jobs=l, oob_score=False,
                           random_state=None, verbose=0, warm_start=False)