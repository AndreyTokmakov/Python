from multiprocessing import Pool, Manager
import time


# Create the Manager Object
mgr = Manager()

def print_numbers(name: str = "Worker",
                  count: int = 10):
    global mgr
    for i in range(count):
        print(f'{name}: {i} | Processes: {mgr.list()}')
        time.sleep(1)

'''
def simple_test():
    with Pool(processes=4) as pool:            # start 4 worker processes
        result = pool.apply_async(func, (10,)) # evaluate "f(10)" asynchronously in a single process
        print(result.get(timeout=1))           # prints "100" unless your computer is *very* slow

        print(pool.map(func, range(10)))       # prints "[0, 1, 4,..., 81]"

        it = pool.imap(func, range(10))
        print(next(it))                     # prints "0"
        print(next(it))                     # prints "1"
        print(it.next(timeout=1))           # prints "4" unless your computer is *very* slow

        result = pool.apply_async(time.sleep, (10,))
        print(result.get(timeout=1))        # raises multiprocessing.TimeoutError
'''

def simple_test():
    with Pool(processes=4) as pool:
        result = pool.apply_async(print_numbers, (["Worker_1"], 10))

        pool.apply_async(print_numbers, (["Worker_2"], 5))
        pool.apply_async(print_numbers, (["Worker_3"], 5))
        pool.apply_async(print_numbers, (["Worker_4"], 5))

        # print(result.get(timeout=1))

        result.wait()

if __name__ == '__main__':
    simple_test()
    pass
