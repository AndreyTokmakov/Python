import datetime

import sqlite3
import time

import requests
from typing import Dict, List, Tuple


def Get_Latest_Rates():
    url = 'https://api.exchangerate.host/latest'
    response = requests.get(url)
    data: Dict = response.json()

    if "success" not in data.keys():
        return None

    return data.get('rates')


def Get_Rate_Insert_To_Database(date: str, currency: str):
    query_params = {'base': currency}
    endpoint = f'https://api.exchangerate.host/{date}'
    response = requests.get(endpoint, params=query_params)
    data = response.json()

    if "success" not in data.keys():
        return False

    query: str = f"INSERT INTO fx_rates (date, currency_code, rates) VALUES ('{date}', '{currency}', \"{data.get('rates')}\")"

    conn = sqlite3.connect('my_database.sqlite')
    cursor = conn.cursor()
    cursor.execute(query)
    conn.commit()
    conn.close()


def get_rates_for_data(date: datetime, currency: str = 'EUR'):
    endpoint = f'https://api.exchangerate.host/{date}'
    response = requests.get(endpoint, params={'base': currency})
    data = response.json()

    if "success" not in data.keys():
        return False
    else:
        return data.get('rates')


def load_fx_rate(start_date: str,
                 end_data: str,
                 currency: str = 'EUR') -> bool:
    rates: List[Tuple] = []
    start, end = datetime.datetime.strptime(start_date, "%Y-%m-%d"), datetime.datetime.strptime(end_data, "%Y-%m-%d")

    for ordinal in range(start.toordinal(), end.toordinal() + 1):
        date = datetime.date.fromordinal(ordinal)
        rates.append((date, currency, get_rates_for_data(date, currency)))

        print(f'Get {date}')
        time.sleep(1)

    with sqlite3.connect('my_database.sqlite') as session:
        cursor = session.cursor()
        for date, _, rate in rates:
            query: str = f"INSERT INTO fx_rates (date, currency_code, rates) VALUES ('{date}','{currency}',\"{rate}\");"
            cursor.execute(query)
        session.commit()


def Create_Database_And_Table():
    conn = sqlite3.connect('my_database.sqlite')
    cursor = conn.cursor()

    cursor.execute('''CREATE TABLE fx_rates
                 (date DATE NOT NULL,
                  currency_code TEXT NOT NULL,
                  rates         TEXT NOT NULL,
                  PRIMARY KEY (date, currency_code))''')
    cursor.close()


def Insert_data_TEST():
    conn = sqlite3.connect('my_database.sqlite')
    cursor = conn.cursor()
    cursor.execute("INSERT INTO fx_rates (date, currency_code, rates) VALUES ('2008-01-01', 'Rohan', '111')")
    conn.commit()
    conn.close()


if __name__ == '__main__':
    # Get_Rate_Insert_To_Database("2022-01-10", "EUR")
    # Create_Database_And_Table()
    # Insert_data_TEST()

    load_fx_rate("2019-01-01", "2019-12-31", 'USD')

    # print(get_rates_for_data("2019-01-01"))

    pass
