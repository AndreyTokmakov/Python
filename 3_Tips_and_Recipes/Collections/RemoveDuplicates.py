

def deduplicate(items):
    seen = set()
    for item in items:
        if item not in seen:
            yield item
            seen.add(item)


def deduplicate_with_key(items, key=None):
    seen = set()
    for item in items:
        val = item if key is None else key(item)
        if val not in seen:
            yield item
            seen.add(val)


''' Problem
You want to eliminate the duplicate values in a sequence, but preserve the order of the
remaining items.
'''

if __name__ == '__main__':
    a = [1, 5, 2, 1, 9, 1, 5, 10]
    x = list(deduplicate(a))
    print(x)

    # b = [{'x': 1, 'y': 2}, {'x': 1, 'y': 3}, {'x': 1, 'y': 2}, {'x': 2, 'y': 4}]
    # x1 = list(deduplicate_with_key(a, key=lambda d: d['x']))
    # print(x1)
