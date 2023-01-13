import abc


class AbstractClass(metaclass=abc.ABCMeta):

    @abc.abstractmethod
    def operation_one(self):
        pass

    @abc.abstractmethod
    def operation_two(self):
        pass

    def template_method(self):
        self.operation_one()
        self.operation_two()
        print("")


class ConcreteClassOne(AbstractClass):

    def operation_one(self):
        print(f"{self.__class__.__name__}:operation_one()")

    def operation_two(self):
        print(f"{self.__class__.__name__}:operation_two()")


class ConcreteClassTwo(AbstractClass):

    def operation_one(self):
        print(f"{self.__class__.__name__}:operation_one()")

    def operation_two(self):
        print(f"{self.__class__.__name__}:operation_two()")


if __name__ == "__main__":
    ConcreteClassOne().template_method()
    ConcreteClassTwo().template_method()
