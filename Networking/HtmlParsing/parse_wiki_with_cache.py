from typing import Dict

# import requests
from bs4 import BeautifulSoup
from datetime import timedelta
from requests_cache import CachedSession

cached_session = CachedSession(
    'currencies_cache',
    # use_cache_dir=True,  # Save files in the default user cache dir
    cache_control=True,  # Use Cache-Control headers for expiration, if available
    expire_after=timedelta(days=1),  # Otherwise expire responses after one day
    allowable_methods=['GET', 'POST'],  # Cache POST requests to avoid sending the same data twice
    allowable_codes=[200, 400],  # Cache 400 responses as a solemn reminder of your failures
    ignored_parameters=['api_key'],  # Don't match this param or save it in the cache
    match_headers=True,  # Match all request headers
    stale_if_error=True,  # In case of request errors, use stale cache data if possible
)


def get_country_scores() -> Dict[str, str]:
    endpoint = "https://en.wikipedia.org/wiki/World_Happiness_Report#2019_report"
    response = cached_session.get(endpoint)

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

    return country_scores


def get_world_currencies() -> Dict[str, str]:
    endpoint = "https://flagsworld.org/world-currencies.html"

    response = cached_session.get(endpoint)
    soup = BeautifulSoup(response.text, 'html.parser')

    world_currencies: Dict[str, str] = {}
    table = soup.find('table', {'class': 'swist2'})
    for row in table.findAll("tr"):
        params = [entry.text for entry in row.findAll('td')]
        world_currencies[params[0]] = params[2]

    return world_currencies


if __name__ == '__main__':
    scores: Dict = get_country_scores()
    print(scores)

    # currencies: Dict = get_world_currencies()
    # print(currencies)
