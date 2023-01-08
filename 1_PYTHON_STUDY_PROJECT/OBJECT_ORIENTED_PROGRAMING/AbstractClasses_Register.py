from abc import ABC, abstractmethod


class Calculation(ABC):

    @abstractmethod
    def add(self):
        pass

    @abstractmethod
    def subtract(self):
        pass


@Calculation.register
class Calculator:

    def __init__(self, a, b):
        self.a = a
        self.b = b

    def add(self):
        print(self.a + self.b)

    # def subtract(self):
    #     print(self.a - self.b)


if __name__ == "__main__":
    take = Calculator(10, 5)
    take.add()
    # subtract method is an abstract method but it is not throwing error due to virtual sub class take.subtract()
    print(issubclass(Calculator, Calculation))  # True
