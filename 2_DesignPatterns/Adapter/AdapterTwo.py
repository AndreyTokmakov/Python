"""
Convert the interface of a class into another interface clients expect.
Adapter lets classes work together that couldn't otherwise because of
incompatible interfaces.
"""

import abc


class Target(metaclass=abc.ABCMeta):
    """
    Define the domain-specific interface that Client uses.
    """

    def __init__(self):
        self.to_be_adapted = ToBeAdapted()

    @abc.abstractmethod
    def request(self):
        pass


class Adapter(Target):

    def request(self):
        self.to_be_adapted.specific_request()


class ToBeAdapted:

    def specific_request(self):
        pass


def main():
    adapter = Adapter()
    adapter.request()


if __name__ == "__main__":
    main()

