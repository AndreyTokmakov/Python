
# The metaclass has access to the name of the class, the parent classes it
# inherits from (bases), and all the class attributes that were defined in the
# class’s body. All classes inherit from object, so it’s not explicitly listed in
# the tuple of base classes:

class Meta(type):
    def __new__(meta, name, bases, class_dict):
        print(f'\nRunning {meta}.__new__ for {name}')
        print(f'Bases classes: {bases}')
        print(f'Classes dict: {class_dict}')
        return type.__new__(meta, name, bases, class_dict)


class Base(metaclass=Meta):
    var1 = 123
    var2 = "Text"

    def foo(self):
        pass


class Derived(Base):
    var3 = 111
    var4 = "Text333"

    def bar(self):
        pass


if __name__ == '__main__':
    b = Base()
    d = Derived()