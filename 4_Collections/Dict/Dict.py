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


if __name__ == '__main__':
    # CreateDictTests();
    # Iterate_Dict()
    # pop();
    # CheckIFKeyExists();

    # UpdateValue_With_Get()

    Add_Default()
    # Add_Default_2()

    # Use_Custom_Class_As_Key()
    # Find_Same_Keys_In_Two_Maps()
