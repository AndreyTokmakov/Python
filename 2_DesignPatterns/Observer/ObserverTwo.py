from __future__ import annotations
from abc import ABC, abstractmethod, ABCMeta
from typing import Set


class IObserver(metaclass=ABCMeta):
    """
    Define an updating interface for objects that should be notified of changes in a subject.
    """

    @abstractmethod
    def update(self, obj: IObservable):
        pass


class IObservable(metaclass=ABCMeta):

    @abstractmethod
    def add_observer(self, observer: IObserver) -> IObserver:
        pass

    @abstractmethod
    def remove_observer(self, observer: IObserver) -> IObserver:
        pass

    @abstractmethod
    def notify(self):
        pass


class ObservableBase(IObservable):

    def __init__(self):
        self.observers: Set[IObserver] = set()

    def add_observer(self, observer: IObserver) -> IObserver:
        self.observers.add(observer)
        return observer

    def remove_observer(self, observer: IObserver) -> IObserver:
        self.observers.discard(observer)
        return observer

    def notify(self):
        for observer in self.observers:
            observer.update(self)


class Subject(ObservableBase):
    """
    Know its observers. Any number of Observer objects may observe a subject.
    Send a notification to its observers when its state changes.
    """

    def __init__(self):
        super().__init__()
        self.__some_internal_state = None

    @property
    def subject_state(self):
        return self.__some_internal_state

    @subject_state.setter
    def subject_state(self, arg):
        self.__some_internal_state = arg
        self.notify()

    def __repr__(self):
        return f'Subject({self.__some_internal_state})'


class ConcreteObserverOne(IObserver):
    """
    Implement the Observer updating interface to keep its state consistent with the subject's.
    Store state that should stay consistent with the subject's.
    """

    def update(self, subj: IObservable):
        print(f"{self.__class__.__name__}::update() for {subj}")


class ConcreteObserverTwo(IObserver):
    """
    Implement the Observer updating interface to keep its state consistent with the subject's.
    Store state that should stay consistent with the subject's.
    """

    def update(self, subj: IObservable):
        print(f"{self.__class__.__name__}::update() for {subj}")


if __name__ == "__main__":
    subject = Subject()

    subject.add_observer(ConcreteObserverOne())
    subject.add_observer(ConcreteObserverTwo())

    subject.subject_state = 123
