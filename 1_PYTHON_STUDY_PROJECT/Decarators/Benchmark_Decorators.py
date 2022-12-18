
import time
import requests


def benchmark(iters):
    def actual_decorator(func):
        def wrapper(*args, **kwargs):
            total = 0
            for i in range(iters):
                start = time.time()
                return_value = func(*args, **kwargs)
                end = time.time()
                total = total + (end - start)
            print('[*] Average execution time: {} seconds.\n'.format(total / iters))
            return return_value

        return wrapper

    return actual_decorator


@benchmark(iters=10)
def fetch_webpage(url):
    webpage = requests.get(url)
    return webpage.text


if __name__ == '__main__':
    webpage = fetch_webpage('https://google.com')
    print(webpage)
