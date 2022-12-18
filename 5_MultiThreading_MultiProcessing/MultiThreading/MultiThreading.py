from concurrent.futures import ThreadPoolExecutor
import threading
from time import sleep


def return_after_5_secs(message):
    sleep(5)
    # return message;
    return True;


if __name__ == '__main__':
    pool = ThreadPoolExecutor(1)

    future = pool.submit(return_after_5_secs, ("hello"))

    print(future.done())
    sleep(0.5)
    print(future.done())
    sleep(0.5)
    print(future.done())
    sleep(0.5)
    print(future.done())
    sleep(0.5)
    print(future.done())
    sleep(0.5)
    print(future.done())
    sleep(0.5)

    res = future.result()
    print(res)

