

import abc
from abc import abstractmethod


class AbstractCar(metaclass=abc.ABCMeta):

    @abstractmethod
    def drive(self):
        raise NotImplementedError("You should implement this.")


class Car(AbstractCar):

    def drive(self) -> None:
        print("Car has been driven!")


class Driver:

    def __init__(self, age: int) -> None:
        self.age = age


class ProxyCar(AbstractCar):

    def __init__(self, driver) -> None:
        self.car = Car()
        self.driver = driver

    def drive(self) -> None:
        if self.driver.age <= 16:
            print("Sorry, the driver is too young to drive.")
        else:
            self.car.drive()


if __name__ == "__main__":
    ProxyCar(Driver(16)).drive()
    ProxyCar(Driver(25)).drive()

