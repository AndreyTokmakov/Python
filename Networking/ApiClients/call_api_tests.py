from typing import Dict

import requests

CATS_API_URL: str = "https://catfact.ninja/"


def test1():
    # api_url = "https://jsonplaceholder.typicode.com/todos/1"
    # api_url = "https://api.thedogapi.com"
    api_url = "https://api.thedogapi.com/v1/breeds"

    response = requests.get(api_url)
    print(response.json())


def test_fact():
    response = requests.get(CATS_API_URL + "fact")
    print(response.text)


def test_facts():
    response = requests.get(CATS_API_URL + "facts",
                            params={"limit": 1})
    print(response.json())


def test_breeds():
    response = requests.get(CATS_API_URL + "breeds",
                            params={"limit": 2})
    data: Dict = response.json()
    print(data['data'])


if __name__ == '__main__':
    # test()
    # test_facts()
    test_breeds()
