
# Is a class of a mixed up pair for which the conditions are met
# 1. UnorderedPair(1, 2) == UnorderedPair(2, 1)
# 2. UnorderedPair(1, 2) == UnorderedPair(1, 2)
class UnorderedPair(object):

    def __init__(self, a, b):
        self.a = a
        self.b = b

    def __eq__(self, other):
        return {other.a, other.b} == {self.a, self.b}

    def __str__(self) -> str:
        return f'[{self.a}, {self.b}]'

    def __hash__(self):
        return hash((self.a, self.b)) + hash((self.b, self.a))
