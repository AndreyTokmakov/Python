"""
Use sharing to support large numbers of fine-grained objects efficiently.
"""

import abc


class FlyweightFactory:
    """
    Create and manage flyweight objects.
    Ensure that flyweights are shared properly. When a client requests a flyweight, the
    FlyweightFactory object supplies an existing instance or creates one, if none exists.
    """

    def __init__(self):
        self.__flyweights = {}

    def get_flyweight(self, name: str):
        return self.__flyweights.get(key, ConcreteFlyweight(key))


class Flyweight(metaclass=abc.ABCMeta):
    """
    Declare an interface through which flyweights can receive and act on extrinsic state.
    """

    def __init__(self, name: str) -> None:
        self.intrinsic_state = None
        self.name = name

    @abc.abstractmethod
    def operation(self, extrinsic_state):
        pass


class ConcreteFlyweight(Flyweight):
    """
    Implement the Flyweight interface and add storage for intrinsic state, if any.
    A ConcreteFlyweight object must be sharable.
    Any state it stores must be intrinsic; that is, it must be independent of the ConcreteFlyweight object's context.
    """

    def operation(self, extrinsic_state):
        print(f'{self.__class__.__name__}({self.name})::operation()')

    def __init__(self, name: str) -> None:
        super().__init__(name)
        print(f'{self.__class__.__name__}({self.name}) created')


if __name__ == "__main__":
    factory = FlyweightFactory()

    for key in ["one", "two", "three", "one", "two", "three"]:
        concrete_flyweight = factory.get_flyweight(key)
        concrete_flyweight.operation(None)
        print()
