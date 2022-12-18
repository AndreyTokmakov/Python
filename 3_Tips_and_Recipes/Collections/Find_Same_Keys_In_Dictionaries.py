""" Problem
You have two dictionaries and want to find out what they might have in common (same
keys, same values, etc.).
"""

if __name__ == '__main__':
    a = {'x': 1, 'y': 2, 'z': 3}
    b = {'w': 10, 'x': 11, 'y': 2}

    print("Common keys: ", a.keys() & b.keys())
    print("Find keys in a that are not in b: ", a.keys() - b.keys())
    print("Find (key,value) pairs in common: ", a.items() & b.items())
