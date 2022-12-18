
from collections import defaultdict


def Simple_Test():
    sites = defaultdict(set)

    sites['England'].add('Bath')
    sites['England'].add('London')
    sites['Russia'].add('Moscow')

    print(sites)
    print(dict(sites))


def List_as_Value():
    d = defaultdict(list)

    d['1'].append('One')
    d['1'].append('I')

    print(d)

def Log_Missing():
    current = {'green': 12, 'blue': 3}
    increments = [
        ('red', 5),
        ('blue', 17),
        ('orange', 9),
    ]

    def log_missing():
        print('Key added')
        return 0

    result = defaultdict(log_missing, current)

    print('Before:', dict(result))
    for key, amount in increments:
        result[key] += amount
    print('After: ', dict(result))


class CountMissing:
    def __init__(self):
        self.added = 0

    def missing(self):
        self.added += 1
        return 0


def Count_Missing_WithClass():
    counter = CountMissing()
    current = {'green': 12, 'blue': 3}
    increments = [
        ('red', 5),
        ('blue', 17),
        ('orange', 9),
    ]

    result = defaultdict(counter.missing, current)
    for key, amount in increments:
        result[key] += amount

    print(counter.added)


if __name__ == '__main__':
    # Simple_Test()
    # Log_Missing()
    # Count_Missing_WithClass()
    List_as_Value()