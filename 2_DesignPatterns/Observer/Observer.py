from __future__ import annotations
from abc import ABC, abstractmethod
from random import randrange
from typing import List


class IObserver(ABC):
    @abstractmethod
    def update(self, subject: IObservable):
        pass


class IObservable(ABC):

    @abstractmethod
    def attach(self, observer: IObserver):
        pass

    @abstractmethod
    def detach(self, observer: IObserver):
        pass

    @abstractmethod
    def notify(self):
        pass


class ObservableBase(IObservable, ABC):

    def __init__(self) -> None:
        self.observers: List[IObserver] = []

    def attach(self, observer: IObserver):
        print("Attached an observer")
        self.observers.append(observer)

    def detach(self, observer: IObserver):
        print("Observer detached")
        self.observers.remove(observer)

    def notify(self):
        for observer in self.observers:
            observer.update(self)


# ------------------------ Concrete classes implementations -----------------


class ConcreteSubject(ObservableBase):

    def __init__(self) -> None:
        super().__init__()
        self.value: int = randrange(0, 10)
        print(f'{self.__class__.__name__}(value: {self.value}) created')

    def some_business_logic(self):
        print("Subject::some_business_logic()")
        # elf.value: int = randrange(0, 10)
        # print(f"Subject: My state has just changed to: {self.value}")

        self.notify()


class ConcreteObserverA(IObserver):

    def update(self, subj: ConcreteSubject):
        if subj.value > 3:
            print(f"{self.__class__.__name__}: Reacted to the event")


class ConcreteObserverB(IObserver):

    def update(self, subj: ConcreteSubject):
        if subj.value > 6:
            print(f"{self.__class__.__name__}: Reacted to the event")


if __name__ == "__main__":
    subject = ConcreteSubject()

    observer_a = ConcreteObserverA()
    subject.attach(observer_a)
    observer_b = ConcreteObserverB()
    subject.attach(observer_b)

    print()

    subject.some_business_logic()
    # subject.some_business_logic()

    print()

    subject.detach(observer_a)

    print()

    subject.some_business_logic()
