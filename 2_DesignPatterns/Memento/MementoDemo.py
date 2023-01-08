from __future__ import annotations
from abc import ABC, abstractmethod
from datetime import datetime
from random import sample
from string import ascii_letters, digits


class Memento(ABC):

    @abstractmethod
    def get_name(self) -> str:
        pass

    @abstractmethod
    def get_date(self) -> str:
        pass

    @abstractmethod
    def get_state(self) -> str:
        pass


class ConcreteMemento(Memento):

    def __init__(self, state: str) -> None:
        self.state = state
        self.date = datetime.now()

    def get_name(self) -> str:
        return f"{self.date} / ({self.state[0:9]}...)"

    def get_date(self) -> datetime:
        return self.date

    def get_state(self) -> str:
        return self.state


class Originator(object):

    state = None

    def __init__(self, state: str) -> None:
        self.state = state
        print(f"Originator: My initial state is: {self.state}")

    def do_something(self) -> None:
        self.state = self.generate_random_string(30)
        print(f"Originator: state has changed to: {self.state}")

    @staticmethod
    def generate_random_string(length: int = 10) -> str:
        return "".join(sample(ascii_letters, length))

    def prepare_state(self) -> Memento:
        return ConcreteMemento(self.state)

    def restore(self,
                memento: Memento) -> None:
        self.state = memento.get_state()
        print(f"Originator: My state has changed to: {self.state}")


class Caretaker(object):

    def __init__(self, originator: Originator) -> None:
        self.mementos = []
        self.originator = originator

    def backup(self) -> None:
        self.mementos.append(self.originator.prepare_state())

    def undo(self) -> None:
        if not len(self.mementos):
            return

        memento = self.mementos.pop()
        try:
            self.originator.restore(memento)
        except Exception:
            self.undo()

    def show_history(self) -> None:
        for memento in self.mementos:
            print(memento.get_name())


if __name__ == "__main__":
    originator = Originator("Super-duper-super-puper-super.")
    caretaker = Caretaker(originator)

    caretaker.backup()
    originator.do_something()

    caretaker.backup()
    originator.do_something()

    caretaker.backup()
    originator.do_something()

    print()
    caretaker.show_history()

    print("\nClient: Now, let's rollback!\n")
    caretaker.undo()

    print("\nClient: Once more!\n")
    caretaker.undo()