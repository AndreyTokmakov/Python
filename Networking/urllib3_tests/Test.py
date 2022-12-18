
import urllib3

if __name__ == '__main__':

    http = urllib3.PoolManager()
    request = http.request('GET', 'http://httpbin.org/robots.txt')

    print(request.status)
    print(request.data)