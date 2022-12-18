

class Unit(object):

    class_var: int = 10
    some_list = []

    def __init__(self, v: int):
        self.instance_var: int = v

    def __repr__(self):
        return f'Unit {self.class_var}, {self.instance_var}, {self.some_list}'

    def add(self, v):
        self.some_list.append(v)


if __name__ == '__main__':

    u1, u2 = Unit(101), Unit(102)

    print(u1)
    print(u2)

    u1.class_var = 5
    u1.add("eee")

    print(u1)
    print(u2)


