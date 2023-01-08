from __future__ import annotations
import abc
from typing import  List


class IComponent(metaclass=abc.ABCMeta):

    @abc.abstractmethod
    def showInfo(self):
        pass

    @abc.abstractmethod
    def add(self, component: IComponent) -> IComponent:
        pass


class Component(IComponent):

    def __init__(self, name: str):
        self.name = name

    def showInfo(self):
        print(self.name)

    def add(self, component: IComponent) -> IComponent:
        pass


class SingleElement(Component):

    def __init__(self, name: str):
        super().__init__(name)


class ElementsGroup(Component):

    def __init__(self, name: str) -> None:
        super().__init__(name)
        self._children: List[IComponent] = []

    def showInfo(self):
        print(self.name + ":")
        for entry in self._children:
            print('  ', end='')
            entry.showInfo()

    def add(self, component: IComponent) -> IComponent:
        self._children.append(component)
        return self


def client_code(component: IComponent):
    component.showInfo()


if __name__ == "__main__":
    c1, c2 = Component("Component1"), Component("Component2")
    group: ElementsGroup = ElementsGroup("Group")
    group.add(c1).add(c2)

    l: List[IComponent] = [c1, c2, group]
    for c in l:
        c.showInfo()
