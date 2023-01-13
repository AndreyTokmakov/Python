import abc
from typing import List


class IElement(metaclass=abc.ABCMeta):
    """ Define an Accept operation that takes a visitor as an argument. """

    @abc.abstractmethod
    def accept(self, visitor):
        pass


class IVisitor(metaclass=abc.ABCMeta):
    """
    Declare a Visit operation for each class of ConcreteElement in the object structure.
    The operation's name and signature identifies the class that sends the Visit request to the visitor.
    That lets the visitor determine the concrete class of the element being visited.
    Then the visitor can access the element directly through its particular interface.
    """

    @abc.abstractmethod
    def visit_concrete_element_a(self, concrete_element_a: IElement):
        pass

    @abc.abstractmethod
    def visit_concrete_element_b(self, concrete_element_b: IElement):
        pass


class ConcreteElementA(IElement):
    """ Implement an Accept operation that takes a visitor as an argument. """

    def accept(self, visitor: IVisitor):
        print(f'{self.__class__.__name__} handling {visitor.__class__.__name__}')
        visitor.visit_concrete_element_a(self)


class ConcreteElementB(IElement):
    """ Implement an Accept operation that takes a visitor as an argument. """

    def accept(self, visitor: IVisitor):
        print(f'{self.__class__.__name__} handling {visitor.__class__.__name__}')
        visitor.visit_concrete_element_b(self)


class ConcreteVisitorOne(IVisitor):

    def visit_concrete_element_a(self, concrete_element_a: IElement):
        print(f'\t{self.__class__.__name__}::visit_concrete_element_a()')

    def visit_concrete_element_b(self, concrete_element_b: IElement):
        print(f'\t{self.__class__.__name__}::visit_concrete_element_b()')


class ConcreteVisitorTwo(IVisitor):

    def visit_concrete_element_a(self, concrete_element_a: IElement):
        print(f'\t{self.__class__.__name__}::visit_concrete_element_a()')

    def visit_concrete_element_b(self, concrete_element_b: IElement):
        print(f'\t{self.__class__.__name__}::visit_concrete_element_b()')


if __name__ == "__main__":

    visitor1, visitor2 = ConcreteVisitorOne(), ConcreteVisitorTwo()
    for element in [ConcreteElementA(), ConcreteElementB()]:
        element.accept(visitor1)
        element.accept(visitor2)

