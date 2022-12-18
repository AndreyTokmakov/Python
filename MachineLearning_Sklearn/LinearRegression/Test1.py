
from sklearn.linear_model import LinearRegression
from sklearn.datasets import load_boston

if __name__ == '__main__':
    # Загрузить данные только с двумя признаками
    boston = load_boston()
    features = boston.data[:,0:2]
    target = boston.target

    # Создать объект линейной регрессии
    regression = LinearRegression()

    # Выполнить подгонку линейной регрессии
    model = regression.fit(features, target)

    print(model.coef_)
    # print(model.intercept_)


    # Предсказать целевое значение первого наблюдения, умноженное на 1000
    print(model.predict(features)[0])