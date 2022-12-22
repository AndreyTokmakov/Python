"""
Separate the construction of a complex object from its representation so
that the same construction process can create different representations.
"""

import abc


class Product:
    """
    Represent the complex object under construction.
    """

    pass


class Builder(metaclass=abc.ABCMeta):
    """
    Specify an abstract interface for creating parts of a Product object.
    """

    def __init__(self):
        self.product: Product = Product()

    @abc.abstractmethod
    def build_part_a(self):
        pass

    @abc.abstractmethod
    def build_part_b(self):
        pass

    @abc.abstractmethod
    def build_part_c(self):
        pass


class ConcreteBuilder(Builder):
    """
    Construct and assemble parts of the product by implementing the
    Builder interface.
    Define and keep track of the representation it creates.
    Provide an interface for retrieving the product.
    """

    def build_part_a(self):
        print("build_part_a")
        pass

    def build_part_b(self):
        print("build_part_b")
        pass

    def build_part_c(self):
        print("build_part_c")
        pass


class Director:
    """
    Construct an object using the Builder interface.
    """

    def __init__(self):
        self._builder = None

    def construct(self, builder: Builder):
        self._builder = builder
        self._builder.build_part_a()
        self._builder.build_part_b()
        self._builder.build_part_c()


if __name__ == "__main__":

    director = Director()

    concrete_builder = ConcreteBuilder()
    director.construct(concrete_builder)
    product = concrete_builder.product
