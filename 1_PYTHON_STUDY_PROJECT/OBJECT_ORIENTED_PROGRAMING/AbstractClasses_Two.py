from abc import ABC, abstractmethod


class Calculation(ABC):

    @abstractmethod
    def add(self):
        pass

    @abstractmethod
    def subtract(self):
        pass

    def multiply(self):
        pass

    def division(self):
        pass


class Calculator(Calculation):

    def __init__(self, a, b):
        self.a = a
        self.b = b

    def add(self):
        print(self.a + self.b)

    def subtract(self):
        print(self.a - self.b)


if __name__ == "__main__":
    take = Calculator(10, 5)
    take.add()
    take.subtract()
