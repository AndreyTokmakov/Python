from time import sleep
from concurrent.futures import ThreadPoolExecutor


def SimpleTest():
    def return_after_5_secs(message):
        sleep(5)
        return True

    pool = ThreadPoolExecutor(1)
    future = pool.submit(return_after_5_secs, ("hello"))

    while True:
        if future.done():
            break
        sleep(0.5)
        print("Waiting")

    print("Done")

    res = future.result()
    print(res)


if __name__ == '__main__':
    SimpleTest()
