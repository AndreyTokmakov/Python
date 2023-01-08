from __future__ import annotations
from abc import ABC, abstractmethod


class Creator(ABC):
    """
    The Creator class declares the factory method that is supposed to return an object of a Product class.
    The Creator's subclasses usually provide the implementation of this method.
    """

    @abstractmethod
    def factory_method(self) -> Product:
        """
        Note that the Creator may also provide some default implementation of the factory method.
        """
        raise Exception("Not implemented")
        # pass

    def some_operation(self) -> str:
        """
        Also note that, despite its name, the Creator's primary responsibility is not creating products.
        Usually, it contains some core business logic that relies on Product objects, returned by the factory method.
        Subclasses can indirectly change that business logic by overriding the factory method and returning
        a different type of product from it.
        """

        ''' Call the factory method to create a Product object. '''
        product = self.factory_method()

        '''Now, use the product.'''
        result = f"Creator: { product.operation() }"

        return result

    def __repr__(self):
        return f'{self.__class__.__name__}'


class Product(ABC):
    """
    The Product interface declares the operations that all concrete products must implement.
    """

    @abstractmethod
    def operation(self) -> str:
        raise Exception("Not implemented")


"""
**** Concrete Products provide various implementations of the Product interface. ***
"""


class ConcreteProductOne(Product):

    def operation(self) -> str:
        return f"[ {self.__class__.__name__}::operation() ]"


class ConcreteProductTwo(Product):

    def operation(self) -> str:
        return f"[ {self.__class__.__name__}::operation() ]"


"""
*** Concrete Creators override the factory method in order to change the resulting product's type. ***
"""


class ConcreteCreatorOne(Creator):
    """
    Note that the signature of the method still uses the abstract product type,
    even though the concrete product is actually returned from the method. This
    way the Creator can stay independent of concrete product classes.
    """

    def factory_method(self) -> Product:
        return ConcreteProductOne()


class ConcreteCreatorTwo(Creator):
    """
    Note that the signature of the method still uses the abstract product type,
    even though the concrete product is actually returned from the method. This
    way the Creator can stay independent of concrete product classes.
    """

    def factory_method(self) -> Product:
        return ConcreteProductTwo()


def client_code(creator: Creator) -> None:
    """
    The client code works with an instance of a concrete creator, albeit through
    its base interface. As long as the client keeps working with the creator via
    the base interface, you can pass it any creator's subclass.
    """

    print(f'\nClient using the {creator} creator')

    result = creator.some_operation()
    print(f"{result}")


if __name__ == "__main__":
    client_code(ConcreteCreatorOne())
    client_code(ConcreteCreatorTwo())
