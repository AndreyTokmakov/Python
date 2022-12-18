from typing import Dict

import requests
from urllib.request import urlopen
# import html5lib
from bs4 import BeautifulSoup


def parse_test1():
    endpoint = "https://en.wikipedia.org/wiki/World_Happiness_Report#2019_report"
    response = requests.get(endpoint)

    # soup = BeautifulSoup(response.text, 'html5lib')
    soup = BeautifulSoup(response.text, 'html.parser')
    print("The object type:", type(soup))

    with open("/home/andtokm/tmp/trace.log", 'a') as file:
        file.write(str(soup))


def find_table():
    endpoint = "https://en.wikipedia.org/wiki/World_Happiness_Report#2019_report"
    response = requests.get(endpoint)

    soup = BeautifulSoup(response.text, 'html.parser')
    title = soup.find('span', {'class': 'mw-headline', 'id': '2019_report'})
    table_2019 = title.find_next('table', {'class': 'wikitable sortable'})
    table_rows = table_2019.findAll("tr")

    headers = [entry.text.strip() for entry in table_rows[0].findAll('th')]
    name_index: int = headers.index('Country or region')
    score_index: int = headers.index('Score')

    country_scores: Dict[str, str] = {}
    for idx in range(1, len(table_rows)):
        row = [entry.text.strip() for entry in table_rows[idx].findAll('td')]
        country_scores[row[name_index]] = row[score_index]

    print(country_scores)


def find_and_parse_table():
    endpoint = "https://en.wikipedia.org/wiki/World_Happiness_Report#2019_report"
    response = requests.get(endpoint)

    soup = BeautifulSoup(response.text, 'html.parser')

    tables = soup.find_all('table', {'class': 'wikitable sortable'})
    table_2019 = tables[1]
    table_rows = table_2019.findAll("tr")

    headers = [entry.text.replace('\n', '') for entry in table_rows[0].findAll('th')]
    print(headers)

    for idx in range(1, len(table_rows)):
        row = [entry.text.replace('\xa0', '').replace('\n', '') for entry in table_rows[idx].findAll('td')]
        print(row)


def parse_test2():
    url = "http://olympus.realpython.org/profiles/dionysus"
    page = urlopen(url)
    html = page.read().decode("utf-8")
    soup = BeautifulSoup(html, "html.parser")
    print(soup)

    image1, image2 = soup.find_all("img")
    print(image1)
    print(image2)


def get_currencies_of_the_world():
    endpoint = "https://flagsworld.org/world-currencies.html"
    response = requests.get(endpoint)
    soup = BeautifulSoup(response.text, 'html.parser')

    table = soup.find('table', {'class': 'swist2'})
    for row in table.findAll("tr"):
        params = [entry.text for entry in row.findAll('td')]
        print(params)

    # with open("/home/andtokm/tmp/trace.log", 'a') as file:
    #     file.write(str(table))


def get_currencies_of_the_world_2():
    # url = 'https://currencyconverts.com/currencies-of-the-world'
    url = 'https://currencyrate.today/different-currencies'
    response = requests.get(url)
    soup = BeautifulSoup(response.text, 'html.parser')
    table = soup.find('table', {'class': 'table table-hover table-striped table-scroll'})

    rows = table.findAll("tr")
    headers = [entry.text.strip() for entry in rows[0].findAll('th')]
    code_index: int = headers.index('Code')
    country_index: int = headers.index('Country name')

    country_codes: Dict[str, str] = {}
    for idx in range(1, len(rows)):
        row = [entry.text.strip() for entry in rows[idx].findAll('td')]
        country_codes[row[country_index]] = row[code_index]

    print(country_codes)



if __name__ == '__main__':
    # parse_test1()
    # parse_test2()
    # find_table()
    # find_and_parse_table()

    # get_currencies_of_the_world()
    get_currencies_of_the_world_2()
