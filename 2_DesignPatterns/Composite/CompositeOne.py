"""
Compose objects into tree structures to represent part-whole hierarchies.
Composite lets clients treat individual objects and compositions of objects uniformly.
"""

import abc
from typing import Set


class Component(metaclass=abc.ABCMeta):
    """
    Declare the interface for objects in the composition.
    Implement default behavior for the interface common to all classes, as appropriate.
    Declare an interface for accessing and managing its child components.
    Define an interface for accessing a component's parent in the recursive structure,
    and implement it if that's appropriate (optional).
    """

    @abc.abstractmethod
    def operation(self):
        pass


class Composite(Component):
    """
    Define behavior for components having children. Store child components.
    Implement child-related operations in the Component interface.
    """

    def __init__(self):
        self._children: Set[Component] = set()

    def operation(self):
        for child in self._children:
            child.operation()

    def add(self, component: Component):
        self._children.add(component)

    def remove(self, component: Component):
        self._children.discard(component)


class Leaf(Component):
    """
    Represent leaf objects in the composition. A leaf has no children.
    Define behavior for primitive objects in the composition.
    """

    def operation(self):
        pass


if __name__ == "__main__":
    leaf = Leaf()
    composite = Composite()
    composite.add(leaf)
    composite.operation()
