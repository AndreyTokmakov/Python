import abc


class IComponent(metaclass=abc.ABCMeta):

    @abc.abstractmethod
    def operation(self) -> str:
        pass


class Component(IComponent):

    def operation(self) -> str:
        return "Component(SOME OPERATION)\n"


class Decorator(Component):
    _component: Component = None

    def __init__(self, component: Component) -> None:
        self._component = component

    @property
    def component(self) -> Component:
        return self._component

    def operation(self):
        return self._component.operation()


class ConcreteDecoratorA(Decorator):

    def operation(self):
        result = str(self.__class__.__name__ + "::operation() start\n")
        result += self.component.operation()
        result += str(self.__class__.__name__ + "::operation() end\n")
        return result


class ConcreteDecoratorB(Decorator):

    def operation(self) -> str:
        result = str(self.__class__.__name__ + "::operation() start\n")
        result += self.component.operation()
        result += str(self.__class__.__name__ + "::operation() end\n")
        return result


def client_code(component: Component) -> None:
    # ...
    print(f"{component.operation()}", end="")
    # ...


if __name__ == "__main__":

    simple = Component()
    client_code(simple)
    print("\n")

    decorator1 = ConcreteDecoratorB(simple)
    decorator2 = ConcreteDecoratorA(decorator1)

    client_code(decorator2)
