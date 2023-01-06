from typing import Dict


def CreateDictTests():
    d1 = {'key1': 1, 'key2': 2}
    print(d1)

    d2 = dict(short='dict', long='dictionary')
    print(d2)

    d3 = dict([(1, 1), (2, 4)])
    print(d3)

    d4 = dict.fromkeys(['a', 'b'])
    print(d4)

    d5 = dict.fromkeys(['a', 'b'], 100)
    print(d5)

    d6 = {a: a ** 2 for a in range(7)}
    print(d6)


def Iterate_Dict():
    values = {'key1': 1, 'key2': 2, 'key3': 3, 'key4': 4, 'key5': 5}
    for entry in values:
        print(entry)

    print("\n----------------------------------")
    for key, value in values.items():
        print(key, " = ", value)

    print("\n----------------------------------Keys:")
    for key in values.keys():
        print(key)


def Pop():
    values = {'key1': 1, 'key2': 2, 'key3': 3, 'key4': 4, 'key5': 5}
    print(values)

    print("POP: ", "key1 = ", values.pop('key1'))
    print(values)


def Get():
    map: Dict[int, str] = {1: "One"}
    print(map)

    # two = map.get(2, "Two")

    two = map.setdefault(2, "Two")

    print(two)

    print(map)


def CheckIFKeyExists():
    values = {'key1': 1, 'key2': 2, 'key3': 3, 'key4': 4, 'key5': 5}
    print(values)

    print("key1 exits: ", "key1" in values)


def UpdateValue_With_Get():
    values = {'key1': 1, 'key2': 2, 'key3': 3, 'key4': 4, 'key5': 5}
    print(values)

    count = values.get('key6', 0)
    values['key6'] = count + 101

    print(values)


class Holder:

    def __init__(self, name: str):
        self.name = name

    def __str__(self):
        return f'Holder({self.name})'

    def __repr__(self):
        return str(self)


def UpdateValue_With_Get_2():
    map = {1: "One", 2: "Two", 3: "Three"}

    val = map.get(2, "Something")
    print(val)

    val = f'[{val}]'

    print(map)


def UpdateValue_With_Get_3():
    map: Dict[int, Holder] = {1: Holder("One"), 2: Holder("Two"), 3: Holder("Three")}

    val = map.get(2, "Something")
    print(val)

    val.name = f'**{val.name}**'

    print(map)


def Add_Default():
    sites = {
        'Mexico': {'Tulum', 'Puerto Vallarta'},
        'Japan': {'Hakone'},
        'France': {'Paris'},
    }

    sites.setdefault('France', set()).add('Arles')
    print(sites)


def Add_Default_2():
    sites = {
        'Mexico': {'Tulum', 'Puerto Vallarta'},
        'Japan': {'Hakone'},
        # 'France': {'Paris111'},
    }

    if (france := sites.get('France')) is None:
        sites['France'] = france = set()
    france.add('Paris222')

    print(sites)


class Node(object):

    def __init__(self, name):
        self.name = name

    def __hash__(self):
        return hash(self.name)

    def __eq__(self, another):
        return hasattr(another, 'name') and self.name == another.name

    def __repr__(self):
        return f'Node({self.name})'


def Use_Custom_Class_As_Key():
    map = {}

    map[Node("123")] = [1, 2]
    map[Node("234")] = [2, 3]
    map[Node("345")] = [4, 5]
    map[Node("345")] = [4, 5, 5]

    print(map)


def Find_Same_Keys_In_Two_Maps():
    a = {'x': 1, 'y': 2, 'z': 3}
    b = {'w': 10, 'x': 11, 'y': 2}

    print(a.keys() & b.keys())  # Find keys in common
    print(a.keys() - b.keys())  # Find keys in a that are not in b
    print(a.items() & b.items())  # Find (key,value) pairs in common


def check_values_by_condition():
    class Data:
        def __init__(self, v: int = 0, n: str = None):
            self.value = v
            self.text = n

        def __repr__(self):
            return f'Data({self.value}, {self.text})'

    map: Dict[int, Data] = {1: Data(1, "One"), 2: Data(2, "Two"), 3: Data(3, "Three")}
    # map: Dict[int, Data] = {1: Data(1, "One"), 2: Data(2), 3: Data(3, "Three")}

    b1: bool = any(d.text is None for d in map.values())

    print(map)
    print(b1)


if __name__ == '__main__':
    # CreateDictTests();
    # Iterate_Dict()
    # Pop()
    # Get()
    # CheckIFKeyExists();

    # UpdateValue_With_Get()
    # UpdateValue_With_Get_2()
    # UpdateValue_With_Get_3()

    # Add_Default()
    # Add_Default_2()

    # Use_Custom_Class_As_Key()
    # Find_Same_Keys_In_Two_Maps()

    check_values_by_condition()
