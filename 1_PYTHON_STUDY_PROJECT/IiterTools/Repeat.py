
import itertools


# Use repeat to output a single value forever, or use the second parameter to
# specify a maximum number of times:
if __name__ == '__main__':
    it = itertools.repeat('hello', 3)
    print(list(it))  # ['hello', 'hello', 'hello']
