import itertools


# Use chain to combine multiple iterators into a single sequential iterator:
if __name__ == '__main__':
    it = itertools.chain([1, 2, 3], [4, 5, 6])
    print(list(it))  # [1, 2, 3, 4, 5, 6]
