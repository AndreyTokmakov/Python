
import itertools


# combinations: returns the unordered combinations of length N with
# unrepeated items from an iterator:
if __name__ == '__main__':
    it = itertools.combinations([1, 2, 3, 4], 2)
    print(list(it))

    it = itertools.combinations([1, 2, 3, 4], 3)
    print(list(it))