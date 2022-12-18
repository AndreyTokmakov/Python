import pandas as pd

if __name__ == '__main__':
    time_index = pd.date_range("01/01/2010", periods=5, freq="M")

    # Создать фрейм данных, задать индекс
    dataframe = pd.DataFrame(index=time_index)

    # Создать признак
    dataframe["цена_акций"] = [1, 2, 3, 4, 5]

    # Вычислить скользящее среднее
    X = dataframe.rolling(window=2).mean()

    print(X)
