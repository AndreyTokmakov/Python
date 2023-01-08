"""
Decouple an abstraction from its implementation so that the two can vary independently.
"""

import abc


class Implementor(metaclass=abc.ABCMeta):
    """
    Define the interface for implementation classes. This interface doesn't have to correspond exactly
    to Abstraction's interface; in fact the two interfaces can be quite different.
    Typically the Implementor interface provides only primitive operations, and Abstraction defines higher-level
    operations based on these primitives.
    """

    @abc.abstractmethod
    def operation_impl(self):
        pass


class Abstraction:
    """
    Define the abstraction's interface.
    Maintain a reference to an object of type Implementor.
    """

    def __init__(self, impl: Implementor):
        self._impl = impl

    def operation(self):
        self._impl.operation_impl()


class ConcreteImplementorA(Implementor):
    """
    Implement the Implementor interface and define its concrete implementation.
    """

    def operation_impl(self):
        print(f'Calling {self.__class__.__name__}::operation_impl()')
        pass


class ConcreteImplementorB(Implementor):
    """
    Implement the Implementor interface and define its concrete implementation.
    """

    def operation_impl(self):
        print(f'Calling {self.__class__.__name__}::operation_impl()')
        pass


def main():
    concrete_implementor_a, concrete_implementor_b = ConcreteImplementorA(), ConcreteImplementorA()

    abstraction = Abstraction(concrete_implementor_a)
    abstraction.operation()

    abstraction = Abstraction(concrete_implementor_b)
    abstraction.operation()


if __name__ == "__main__":
    main()
