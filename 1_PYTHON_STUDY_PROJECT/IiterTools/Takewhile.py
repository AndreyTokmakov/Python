
import itertools


# dropwhile ,
# which is the opposite of takewhile , skips items from an iterator
# until the predicate function returns True for the first time:
if __name__ == '__main__':
    values = [1, 2, 3, 4, 5, 6, 7, 8, 9, 10]
    it = itertools.takewhile(lambda x: x < 7, values)
    print(list(it))  # [1, 2, 3, 4, 5, 6]
