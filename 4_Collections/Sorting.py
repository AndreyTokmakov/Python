class Data:
    def __init__(self, name, value):
        self.name = name
        self.value = value

    def __repr__(self):
        return f'Data({self.name!r}, {self.value})'


if __name__ == '__main__':
    data_list = [
        Data('drill', 4),
        Data('circular saw', 5),
        Data('jackhammer', 40),
        Data('sander', 7),
    ]

    print(data_list)

    data_list.sort(key=lambda x: x.name)
    print("\nSorted by name: ", data_list)

    data_list.sort(key=lambda x: x.value)
    print("\nSorted by value: ", data_list)

    data_list.sort(key=lambda x: (x.name, x.value))
    print("\nSorted by Tuple(x.name, x.value): ", data_list)
