cities = ['Amsterdam', 'Berlin', 'Venice', 'Glasgow', 'Dublin']


def simple_for():
    for entry in cities:
        print(entry)


def for_by_index():
    size = len(cities)
    for idx in range(size):
        print(f'cities[{idx}] = ', cities[idx])


def enumerate_test():
    for idx, entry in enumerate(cities):
        print(idx, ' -> ', entry)


if __name__ == '__main__':
    # simple_for()
    # for_by_index()
    enumerate_test()
