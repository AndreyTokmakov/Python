"""
Attach additional responsibilities to an object dynamically.
Decorators provide a flexible alternative to subclassing for extending functionality.
"""

import abc


class Component(metaclass=abc.ABCMeta):
    """
    Define the interface for objects that can have responsibilities added to them dynamically.
    """

    @abc.abstractmethod
    def operation(self):
        pass


class Decorator(Component, metaclass=abc.ABCMeta):
    """
    Maintain a reference to a Component object and define an interface that conforms to Component's interface.
    """

    def __init__(self, component: Component):
        self._component = component

    @abc.abstractmethod
    def operation(self):
        pass


class ConcreteDecoratorA(Decorator):
    """
    Add responsibilities to the component.
    """

    def operation(self):
        print('DecoratorA begin')
        self._component.operation()
        print('DecoratorA end')


class ConcreteDecoratorB(Decorator):
    """
    Add responsibilities to the component.
    """

    def operation(self):
        print('   DecoratorB begin')
        self._component.operation()
        print('   DecoratorB end')


class ConcreteComponent(Component):
    """
    Define an object to which additional responsibilities can be attached.
    """

    def operation(self):
        print("   *** Operation to decorate ***")
        pass


def Test1():
    concrete_component = ConcreteComponent()
    concrete_decorator_a = ConcreteDecoratorA(concrete_component)
    concrete_decorator_a.operation()


def Test2():
    concrete_component = ConcreteComponent()
    concrete_decorator_b = ConcreteDecoratorB(concrete_component)
    concrete_decorator_a = ConcreteDecoratorA(concrete_decorator_b)
    concrete_decorator_a.operation()


if __name__ == "__main__":
    print("\n")
    Test1()

    print("\n")
    Test2()
