import pandas as pd
import numpy as np

if __name__ == '__main__':
    # Создать дату
    time_index = pd.date_range("01/01/2010", periods=5, freq="M")

    # Создать фрейм данных, задать индекс
    dataframe = pd.DataFrame(index=time_index)

    # Создать признак с промежутком пропущенных значений
    dataframe["продажи"] = [1.0, 2.0, np.nan, np.nan, 5.0]

    print(dataframe, "\n=======================================================")

    # Интерполировать пропущенные значения
    X = dataframe.interpolate()

    print(X)
