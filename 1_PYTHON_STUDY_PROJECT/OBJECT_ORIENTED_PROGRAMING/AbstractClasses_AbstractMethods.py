from abc import ABC, abstractmethod


class Interface(ABC):

    @abstractmethod
    def call(self):
        raise NotImplemented("Interface::call() method shall be implemented")


class Base(Interface):

    # @abstractmethod
    def call(self):
        print("Base::call()")


class Derived(Base):

    def call(self):
        super().call()
        print("Derived::call()")


class Tests:

    @staticmethod
    def call_non_implemented():
        obj = Interface()
        obj.call()

    @staticmethod
    def call_base_class_method():
        obj = Base()
        obj.call()  # throws if Base::call() is marked as @abstractmethod

    @staticmethod
    def call_derived_class_method():
        obj = Derived()
        obj.call()


if __name__ == "__main__":
    # Tests.call_non_implemented()
    # Tests.call_base_class_method()
    Tests.call_derived_class_method()
