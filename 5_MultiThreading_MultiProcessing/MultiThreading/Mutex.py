import time
from threading import Thread, Lock


def task(idx: int, mtx: Lock):
    mtx.acquire(1)
    time.sleep(1)
    print(f'Thread {idx}')
    mtx.release()


if __name__ == '__main__':
    mutex: Lock = Lock()
    for i in range(10):
        t: Thread = Thread(target=task, args=(i, mutex))
        t.start()
        print(f'Main loop {i}')
