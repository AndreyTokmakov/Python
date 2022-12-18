# Импортируем библиотеки
from sklearn import datasets
import matplotlib.pyplot as plt

# https://proglib.io/p/unsupervised-ml-with-python

if __name__ == '__main__':
    # Загружаем набор данных
    iris_df = datasets.load_iris()

    print(dir(iris_df))              # Методы, доступные для набора данных
    print(iris_df.feature_names)     # Признаки
    print(iris_df.target)            # Метки
    print(iris_df.target_names)      # Имена меток

    # Разделение набора данных
    x_axis = iris_df.data[:, 0]  # Sepal Length
    y_axis = iris_df.data[:, 1]  # Sepal Width

    # Построение
    plt.xlabel(iris_df.feature_names[0])
    plt.ylabel(iris_df.feature_names[1])
    plt.scatter(x_axis, y_axis, c=iris_df.target)
    plt.show()
