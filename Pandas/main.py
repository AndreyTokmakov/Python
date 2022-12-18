from datetime import datetime

import pandas as pd
import numpy as np


DATA_FILE = "./data/shmya_final_version.csv"
data = pd.read_csv(DATA_FILE)

'''
def Get_Column_ByName():
    part = data.head()

    # print(data.head())
    print(part.date)
'''


def Filter_AND_Condition():
    filtered = data[(data['cutlery'] > 2) &
                    (data['order_price'] > 800) &
                    (data['date'] > '2022-01-01')]
    print(filtered)


def Test1():
    filtered = data[data.date.dt.strftime('%Y-%m-%d') == '2022-01-01']
    print(len(filtered))


if __name__ == '__main__':
    # Get_Column_ByName()
    # Filter_AND_Condition()
    Test1();
