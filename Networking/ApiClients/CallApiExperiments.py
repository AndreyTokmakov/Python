import requests

endpoint: str = "http://localhost:52525"
# endpoint: str = 'https://httpbin.org/post'


def simple_request_GET():
    response = requests.get(endpoint)
    if 200 == response.status_code:  # HTTP_OK
        print(response.text)
        # print(response.json())
    else:
        print(f"Error {response.status_code}")


def simple_request_POST():
    query_params = {"param1": "value1", "param2": "value2"}

    response = requests.post(endpoint + "/api/entities", params=query_params)
    if 200 == response.status_code:  # HTTP_OK
        # print(response.text)
        print(response.json())
    else:
        print(f"Error {response.status_code}")




'''
def test1():
    response = requests.get(endpoint, params=query_params)
    print(response)
    # print(response.json())
'''

if __name__ == '__main__':
    # simple_request_GET()
    simple_request_POST()
