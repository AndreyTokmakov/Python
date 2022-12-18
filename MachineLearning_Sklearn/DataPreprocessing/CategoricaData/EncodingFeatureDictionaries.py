
import pandas as pd
from sklearn.feature_extraction import DictVectorizer

if __name__ == '__main__':
    # Create a dictionary
    data_dict = [{"red": 2, "blue": 4},
                 {"red": 4, "blue": 3},
                 {"red": 1, "yellow": 2},
                 {"red": 2, "yellow": 2}]

    # Create a dictionary vectorizer
    vectorizer = DictVectorizer(sparse=False)

    # Convert dictionary to feature matrix
    features = vectorizer.fit_transform(data_dict)

    pd.DataFrame(features, columns=feature_names)

    print(features)