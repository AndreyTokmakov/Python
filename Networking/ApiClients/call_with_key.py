import requests


def get_exchangeratesapi():
    api_key: str = "68b946e7c0b270e8db0997d59a719c89"
    query_params = {"access_key": api_key, "base": "GBP", "symbols": "USD,CAD,EUR"}
    endpoint = f'https://api.exchangeratesapi.io/v1/2013-12-24'

    response = requests.get(endpoint, params=query_params)
    print(response)
    print(response.json())


def get_Exchange_Rate_API():
    query_params = {}
    endpoint = f'https://open.er-api.com/v6/latest/USD'

    response = requests.get(endpoint, params=query_params)
    print(response)
    print(response.json())


def get_Exchange_Rate_API_Historical():
    query_params = {}
    api_key: str = '2d86c75965019119d2abb762'
    endpoint = f'https://v6.exchangerate-api.com/v6/{api_key}/history/USD/2022/10/11'

    response = requests.get(endpoint, params=query_params)
    print(response)
    print(response.json())


def get_photos():
    endpoint = "https://api.nasa.gov/mars-photos/api/v1/rovers/curiosity/photos"
    api_key = "DEMO_KEY"
    query_params = {"api_key": api_key, "earth_date": "2020-07-01"}
    response = requests.get(endpoint, params=query_params)
    print(response)
    print(response.json())


def get_currencylayer_rates():
    api_key: str = '529898fe39e3a39a2c5b3f22b90708aa'
    query_params = {'access_key': api_key, 'date': '2022-04-10'}
    endpoint = f'http://api.currencylayer.com/historical'

    response = requests.get(endpoint, params=query_params)
    print(response)
    print(response.json())


def Get_Exchangerate():
    url = 'https://api.exchangerate.host/latest'
    response = requests.get(url)
    data = response.json()

    print(data)

def Get_Exchangerate_Historical():
    query_params = {'base': 'USD'}
    endpoint = 'https://api.exchangerate.host/2022-04-10'
    response = requests.get(endpoint, params=query_params)
    data = response.json()

    print(data)


# https://proglib.io/p/python-i-api-prevoshodnoe-kombo-dlya-avtomatizacii-raboty-s-publichnymi-dannymi-2021-02-26
if __name__ == '__main__':
    # get_photos()
    # get_exchangeratesapi()

    # get_Exchange_Rate_API()
    # get_Exchange_Rate_API_Historical()
    # get_currencylayer_rates()

    # Get_Exchangerate()
    Get_Exchangerate_Historical()   # INFO: Best !! Look like free
