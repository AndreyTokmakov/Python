import pandas as pd
from sklearn import datasets
from sklearn.model_selection import train_test_split
from sklearn.ensemble import RandomForestClassifier

if __name__ == '__main__':
    # загрузка датасета
    iris = datasets.load_iris()

    print(iris.target_names)
    print(iris.feature_names)

    # вывод первых пяти строк используемого набора данных, а также всех значений целевой переменной датасета.
    data = pd.DataFrame({'sepal length': iris.data[:, 0],
                         'sepal width': iris.data[:, 1],
                         'petal length': iris.data[:, 2],
                         'petal width': iris.data[:, 3],
                         'species': iris.target})
    print(data.head())

    # Далее мы разделяем столбцы на зависимые и независимые переменные (признаки и метки целевых классов).
    # Затем давайте создадим выборки для обучения и тестирования из исходных данных.
    X = data[['sepal length', 'sepal width', 'petal length', 'petal width']]
    y = data['species']

    X_train, X_test, y_train, y_test = train_test_split(X, y, test_size=0.3, random_state=85)

    clf = RandomForestClassifier(n_estimators=100)
    clf.fit(X_train, y_train)
    y_pred = clf.predict(X_test)

    print(y_pred )