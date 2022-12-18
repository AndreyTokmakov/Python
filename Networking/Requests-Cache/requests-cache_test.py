import time

import requests
import sqlite3
from datetime import timedelta
from requests_cache import CachedSession

demo_session_with_cache = CachedSession(
    'demo_cache',
    # use_cache_dir=True,  # Save files in the default user cache dir
    cache_control=True,  # Use Cache-Control headers for expiration, if available
    expire_after=timedelta(days=1),  # Otherwise expire responses after one day
    allowable_methods=['GET', 'POST'],  # Cache POST requests to avoid sending the same data twice
    allowable_codes=[200, 400],  # Cache 400 responses as a solemn reminder of your failures
    ignored_parameters=['api_key'],  # Don't match this param or save it in the cache
    match_headers=True,  # Match all request headers
    stale_if_error=True,  # In case of request errors, use stale cache data if possible
)


def simple_demo():
    session = requests.Session()

    for i in range(5):
        session.get('http://httpbin.org/delay/1')
        print(i)

    session_with_cache = CachedSession('demo_cache')
    for i in range(5):
        session_with_cache.get('http://httpbin.org/delay/1')
        print(i)


def run_tests_on_local_server():
    host: str = "http://localhost:8080"

    '''
    session = requests.Session()
    for _ in range(10):
        r = session.get(host)
        # print(r)
        print(r.content)
        time.sleep(0.25)
    '''

    print('------------------- Using cache ----------------------------')

    session_with_cache = CachedSession('demo_cache')
    for _ in range(10):
        r = demo_session_with_cache.get(host)
        print(r.content)
        time.sleep(0.25)


def check_cache():
    # session = CachedSession('demo_cache', use_memory=True)
    # session = CachedSession('demo_cache')
    # session = CachedSession()

    # print(session.cache.urls)
    for url in demo_session_with_cache.cache.urls:
        print(url)


def read_sql_file():
    conn = sqlite3.connect(r'demo_cache.sqlite')
    cur = conn.cursor()

    print(cur)


def check_caching_by_request_params():
    endpoint: str = "http://localhost:8080"
    api_key: str = '529898fe39e3a39a2c5b3f22b90708aa'
    query_params = {'access_key': api_key, 'date': '2022-04-10'}

    r = demo_session_with_cache.get(endpoint, params=query_params)
    print(r.content)


if __name__ == '__main__':
    # simple_demo()
    # check_cache()
    # read_sql_file()
    # run_tests_on_local_server()
    check_caching_by_request_params()
