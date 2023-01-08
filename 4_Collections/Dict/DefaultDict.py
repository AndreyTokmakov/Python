from collections import defaultdict
from typing import Dict


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


def Get():
    d: Dict[int, str] = defaultdict(str)

    d[1] = 'One'
    d[2] = 'Two'

    print(d.get(3, "Tree"))

    for k, v in d.items():
        print(k, v)


class Holder:

    def __init__(self, name: str = ""):
        self.name = name

    def __str__(self):
        return f'Holder({self.name})'

    def __repr__(self):
        return str(self)


def update_exising_add_missing():
    map: Dict[int, Holder] = defaultdict(Holder)

    h1 = map[1]
    print(map)

    h1.name = "New"
    print(map)

if __name__ == '__main__':
    # Simple_Test()
    # Log_Missing()
    # Count_Missing_WithClass()
    # List_as_Value()
    # Get()

    update_exising_add_missing()

    pass
