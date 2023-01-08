
import itertools


# Use cycle to repeat an iterator’s items forever:
if __name__ == '__main__':
    it = itertools.cycle([1, 2])
    result = [next(it) for _ in range(10)]
    print(result)   #  [1, 2, 1, 2, 1, 2, 1, 2, 1, 2]

