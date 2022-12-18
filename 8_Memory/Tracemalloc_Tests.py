
import os
import gc
import tracemalloc


class MyObject:
    def __init__(self):
        self.data = os.urandom(100)

def get_data():
    values = []
    for _ in range(100):
        obj = MyObject()
        values.append(obj)

    return values

def run():
    deep_values = []
    for _ in range(100):
        deep_values.append(get_data())
    return deep_values


def GC_Test():
    found_objects = gc.get_objects()
    print('Before:', len(found_objects))

    hold_reference = run()
    found_objects = gc.get_objects()

    print('After: ', len(found_objects))
    for obj in found_objects[:3]:
        print(repr(obj)[:100])


def TraceMalloc_Test():
    tracemalloc.start(10)

    # Set stack depth
    time1 = tracemalloc.take_snapshot()

    # Before snapshot
    x = run()
    time2 = tracemalloc.take_snapshot()  # Usage to debug

    # After snapshot
    stats = time2.compare_to(time1, 'lineno')
    for stat in stats[:3]:
        print(stat)


if __name__ == '__main__':
    # GC_Test()
    TraceMalloc_Test()