"""
Provide an interface for creating families of related or dependent
objects without specifying their concrete classes.
"""

from __future__ import annotations
import abc


class AbstractFactory(metaclass=abc.ABCMeta):
    """
    Declare an interface for operations that create abstract product objects.
    """

    @abc.abstractmethod
    def create_product_a(self) -> AbstractProductA:
        pass

    @abc.abstractmethod
    def create_product_b(self) -> AbstractProductB:
        pass


class ConcreteFactory1(AbstractFactory):
    """
    Implement the operations to create concrete product objects.
    """

    def create_product_a(self):
        return ConcreteProductA1()

    def create_product_b(self):
        return ConcreteProductB1()


class ConcreteFactory2(AbstractFactory):
    """
    Implement the operations to create concrete product objects.
    """

    def create_product_a(self):
        return ConcreteProductA2()

    def create_product_b(self):
        return ConcreteProductB2()


class AbstractProductA(metaclass=abc.ABCMeta):
    """
    Declare an interface for a type of product object.
    """

    @abc.abstractmethod
    def interface_a(self):
        pass


class ConcreteProductA1(AbstractProductA):
    """
    Define a product object to be created by the corresponding concrete factory.
    Implement the AbstractProduct interface.
    """

    def interface_a(self):
        print("ConcreteProductA1::interface_a()")
        pass


class ConcreteProductA2(AbstractProductA):
    """
    Define a product object to be created by the corresponding concrete factory.
    Implement the AbstractProduct interface.
    """

    def interface_a(self):
        print("ConcreteProductA2::interface_a()")
        pass


class AbstractProductB(metaclass=abc.ABCMeta):
    """
    Declare an interface for a type of product object.
    """

    @abc.abstractmethod
    def interface_b(self):
        pass


class ConcreteProductB1(AbstractProductB):
    """
    Define a product object to be created by the corresponding concrete factory.
    Implement the AbstractProduct interface.
    """

    def interface_b(self):
        print("ConcreteProductB1::interface_b()")
        pass


class ConcreteProductB2(AbstractProductB):
    """
    Define a product object to be created by the corresponding concrete factory.
    Implement the AbstractProduct interface.
    """

    def interface_b(self):
        print("ConcreteProductB2::interface_b()")
        pass


if __name__ == "__main__":
    for factory in [ConcreteFactory1(), ConcreteFactory2()]:
        product_a = factory.create_product_a()
        product_b = factory.create_product_b()
        product_a.interface_a()
        product_b.interface_b()
