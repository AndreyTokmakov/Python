
import itertools


# permutations: returns the unique ordered permutations of length N with
# items from an iterator:
if __name__ == '__main__':
    it = itertools.permutations([1, 2, 3, 4], 2)
    print(list(it))

    it = itertools.permutations([1, 2, 3, 4], 3)
    print(list(it))
