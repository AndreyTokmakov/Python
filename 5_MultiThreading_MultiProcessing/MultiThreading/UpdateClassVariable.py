import time
from threading import Thread


class Worker(object):

    def __init__(self) -> None:
        self.counter: int = 0

        self.T1: Thread = Thread(target=self.updater, args=())
        self.T2: Thread = Thread(target=self.reader, args=())

        self.T1.start()
        self.T2.start()

    def updater(self):
        while True:
            self.counter += 1
            time.sleep(0.1)
            print(f'UPDATE: counter: {self.counter} {id(self.counter)}')

    def reader(self):
        while True:
            print(f'PRINT: counter: {self.counter} {id(self.counter)}')
            time.sleep(1)


if __name__ == '__main__':

    w = Worker()

