import array
from datetime import datetime
from time import sleep
from typing import Set, Dict, Container, List


class SET_Tests(object):

    def create(self):
        numbers_set = {1, 2, 2, 3, 3}
        print(numbers_set)

    def list_to_set(self):
        list1 = [1, 2, 2, 3, 3, 4, 4, 5, 5]
        list2 = [3, 3, 4, 4, 5, 5, 6, 6, 7, 7]

        set1 = set(list1)
        set2 = set(list2)

        print(list1, " ==> ", set1)
        print(list2, " ==> ", set2)

    def difference(self):
        set1 = {1, 2, 3, 4, 5}
        set2 = {3, 4, 5, 6, 7}

        print("SET 1: ", set1, ", SET 2: ", set2)
        print("Diff 1: ", set1.difference(set2))
        print("Diff 2: ", set2.difference(set1))

    def union(self):
        set1 = {1, 2, 3, 4, 5}
        set2 = {3, 4, 5, 6, 7}

        print("SET 1: ", set1, ", SET 2: ", set2)
        print("union 1: ", set1.union(set2))
        print("union 2: ", set2.union(set1))

    def TESTS(self):
        set1 = {1, 2, 3, 4, 5}
        set2 = {3, 4, 5, 6, 7}

        print("Minus 1: ", set1 - set2)
        print("Minus 2: ", set2 - set1)


class Loops(object):

    def loop1(self):
        str = "qwerty"
        for s in str:
            print(s)


class Strings(object):

    def loop1(self):
        str = "qwerty"
        for s in str:
            print(s)


def log(message, when=datetime.now()):
    print(f'{when}: {message}')


'''
class Meta(type):
    def __new__(meta, name, bases, class_dict):
        print(f'* Running {meta}.__new__ for {name}')
        print('Bases:', bases)
        print(class_dict)
        return type.__new__(meta, name, bases, class_dict)


class MyClass(metaclass=Meta):
    var1 = 123
    var2 = "Text"

    def foo(self):
        pass


class MySubclass(MyClass):
    var3 = 111
    var4 = "Text333"

    def bar(self):
        pass
'''


class Ten:
    def __get__(self, obj, objtype=None):
        return 10


class A:
    x = 5  # Regular class attribute
    y = Ten()  # Descriptor instance


def solution(sentence: str):
    for p in "!?',;.":
        sentence = sentence.replace(p, '')
    print(sentence)


class Node(object):

    def __init__(self, n: str) -> None:
        self.name = n
        self.children = set()

    def __repr__(self) -> str:
        return f'Value({self.name}, Nodes: {self.children})'

    def __hash__(self) -> int:
        return hash(self.name)

    def __eq__(self, another) -> bool:
        return hasattr(another, 'name') and self.name == another.name


class CategoryTree:

    def __init__(self) -> None:
        self.nodes: Dict[str, Node] = {}

    def add(self, parent, child) -> None:
        parent_node = self.nodes.get(parent)
        if parent_node is None:
            self.nodes[parent] = parent_node = Node(parent)

        child_node = self.nodes.get(child)
        if child_node is None:
            self.nodes[child] = child_node = Node(child)
        else:
            pass  # TODO: error?

        parent_node.children.add(child_node)

    def print(self):
        print(self.nodes)


def find_anagrams(word: str,
                  dictionary: Container[str]) -> List[str]:
    """Find all anagrams for a word.

    This function only runs as fast as the test for
    membership in the 'dictionary' container.

    Args:
        word: Target word.
        dictionary: All known actual words.
    Returns:
        Anagrams that were found
    """
    pass


class Value:
    id: int = 0

    def __init__(self, ix: int):
        self.id = ix

    def __repr__(self):
        return f'Value({self.id})'

    def __str__(self):
        return f'Value({self.id})'


def create_generator():
    mylist = range(3)
    for i in mylist:
        yield i * i


def alisa_team(devs_count: int) -> None:
    assert devs_count >= 3, "Error"
    print("OK")


if __name__ == '__main__':
    # setTests = SET_Tests();
    # setTests.create()
    # setTests.list_to_set()
    # setTests.difference()
    # setTests.union()
    # setTests.TESTS()

    # loops = Loops();
    # loops.loop1()

    # alisa_team(3)

    numbers = [1, 2, 3, 4, 5, 6]
    result: bool = any(x > 5 for x in numbers)
    print(result)
