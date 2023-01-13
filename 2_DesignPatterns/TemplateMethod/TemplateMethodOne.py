from abc import ABC, abstractmethod


class BaseAbstractClass(ABC):
    """
    The Abstract Class defines a template method that contains a skeleton of
    some algorithm, composed of calls to (usually) abstract primitive operations.

    Concrete subclasses should implement these operations, but leave the template method itself intact.
    """

    def template_method(self) -> None:
        """
        The template method defines the skeleton of an algorithm.
        """

        self.base_operation1()
        self.required_operations_one()
        self.base_operation2()
        self.hook1()
        self.required_operations_two()
        self.base_operation3()
        self.hook2()

    # These operations already have implementations.

    def base_operation1(self) -> None:
        print(f"BaseAbstractClass: I am doing the bulk of the work")

    def base_operation2(self) -> None:
        print(f"BaseAbstractClass:: But I let subclasses override some operations")

    def base_operation3(self) -> None:
        print(f"BaseAbstractClass:: But I am doing the bulk of the work anyway")

    # These operations have to be implemented in subclasses.

    @abstractmethod
    def required_operations_one(self) -> None:
        pass

    @abstractmethod
    def required_operations_two(self) -> None:
        pass

    # These are "hooks." Subclasses may override them, but it's not mandatory
    # since the hooks already have default (but empty) implementation. Hooks
    # provide additional extension points in some crucial places of the
    # algorithm.

    def hook1(self) -> None:
        pass

    def hook2(self) -> None:
        pass


class ConcreteClass1(BaseAbstractClass):
    """
    Concrete classes have to implement all abstract operations of the base
    class. They can also override some operations with a default implementation.
    """

    def required_operations_one(self) -> None:
        print(f"{self.__class__.__name__}: Implemented Operation1")

    def required_operations_two(self) -> None:
        print(f"{self.__class__.__name__}: Implemented Operation2")


class ConcreteClass2(BaseAbstractClass):
    """
    Usually, concrete classes override only a fraction of base class'
    operations.
    """

    def required_operations_one(self) -> None:
        print(f"{self.__class__.__name__}: Implemented Operation1")

    def required_operations_two(self) -> None:
        print(f"{self.__class__.__name__}: Implemented Operation2")

    def hook1(self) -> None:
        print(f"{self.__class__.__name__}: Overridden Hook1")


def client_code(abstract_class: BaseAbstractClass) -> None:
    # ...
    abstract_class.template_method()
    # ...


if __name__ == "__main__":
    client_code(ConcreteClass1())
    print()
    client_code(ConcreteClass2())