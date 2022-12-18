
import time
from multiprocessing import Process

def print_numbers(name: str = "Worker",
                  count: int = 10):
    for i in range(count):
        print(f'{name}: {i}')
        time.sleep(1)


def run_task():
    proc: Process = Process(target=print_numbers, args=(["Task_1", 2]), name="print_numbers")
    proc.start()

    print(proc.name, proc.pid, proc.is_alive())
    proc.join()
    print(proc.name, proc.pid, proc.is_alive())


def create_empty_process_and_run():
    proc: Process = Process()

    proc.args=(["Task_1", 2]),
    proc.target = print_numbers
    proc.name="print_numbers"

    proc.start()
    proc.join()





if __name__ == '__main__':
    # run_task()
    create_empty_process_and_run()