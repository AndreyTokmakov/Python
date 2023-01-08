"""
Capture and externalize an object's internal state so that the object
can be restored to this state later, without violating encapsulation.
"""

import pickle


class Originator:
    """
    Create a memento containing a snapshot of its current internal state.
    Use the memento to restore its internal state.
    """

    def __init__(self):
        self.state = False

    def set_memento(self, memento):
        previous_state = pickle.loads(memento)
        vars(self).clear()
        vars(self).update(previous_state)

    def create_memento(self):
        return pickle.dumps(vars(self))


if __name__ == "__main__":
    originator = Originator()
    print(originator.state)

    memento = originator.create_memento()
    originator.state = True

    print(originator.state)

    originator.set_memento(memento)
    print(originator.state)