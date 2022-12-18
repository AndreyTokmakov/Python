from threading import Thread, Lock

lock = Lock()
counter: int = 0


def increment():
    global counter
    lock.acquire()
    for _ in range(0, 1000000):
        counter += 1
    lock.release()


def increment_no_synch():
    global counter
    for _ in range(0, 1000000):
        counter += 1


def Test_Good():
    thread1 = Thread(target=increment)
    thread2 = Thread(target=increment)

    thread1.start()
    thread2.start()

    thread1.join()
    thread2.join()

    print('done')
    print(counter)


def Test_Bad():
    thread1 = Thread(target=increment_no_synch)
    thread2 = Thread(target=increment_no_synch)

    thread1.start()
    thread2.start()

    thread1.join()
    thread2.join()

    print('done')
    print(counter)


if __name__ == '__main__':
    # Test_Good()
    Test_Bad()

