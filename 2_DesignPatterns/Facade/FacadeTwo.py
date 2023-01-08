
class Facade:

    def __init__(self):
        self._subsystem_1 = Subsystem1()
        self._subsystem_2 = Subsystem2()

    def operation(self):
        self._subsystem_1.operation1()
        self._subsystem_1.operation2()
        self._subsystem_2.operation1()
        self._subsystem_2.operation2()


class Subsystem1:

    def operation1(self):
        print(f"{self.__class__.__name__}: operation1()")

    def operation2(self):
        print(f"{self.__class__.__name__}: operation2()")


class Subsystem2:

    def operation1(self):
        print(f"{self.__class__.__name__}: operation1()")

    def operation2(self):
        print(f"{self.__class__.__name__}: operation2()")


if __name__ == "__main__":
    facade = Facade()
    facade.operation()
