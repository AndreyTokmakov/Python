
class Meta(type):
    def __new__(meta, name, bases, class_dict):
        print(f'* Running {meta}.__new__ for {name}')
        print('Bases:', bases)
        print(class_dict, '\n\n')
        return type.__new__(meta, name, bases, class_dict)


class MyClass(metaclass=Meta):
    stuff = 123

    def foo(self):
        pass


class MySubclass(MyClass):
    other = 567

    def bar(self):
        pass



if __name__ == "__main__":
    pass