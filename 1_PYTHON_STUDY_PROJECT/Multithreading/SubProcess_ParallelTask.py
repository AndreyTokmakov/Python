
import time

from multiprocessing import Process, Queue

def work():
    for i in range(0, 10):
        print(i)
        time.sleep(1)

def run_task():
    # queue = Queue()
    p = Process(target=work, args=())
    p.start()
    # p.join() # this blocks until the process terminates
    # result = queue.get()
    return p




if __name__ == '__main__':
    task = run_task()
    for i in range(0, 10):
        print(f"Test {i}")
        time.sleep(1)

    task.join()