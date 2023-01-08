
import itertools


# filterfalse ,
# which is the opposite of the filter built-in function, returns
# all items from an iterator where a predicate function returns False :
if __name__ == '__main__':
    values = [1, 2, 3, 4, 5, 6, 7, 8, 9, 10]
    evens = lambda x: x % 2 == 0

    print('Filter: ', list(filter(evens, values)))

    filter_false_result = itertools.filterfalse(evens, values)
    print('Filter false:', list(filter_false_result))
