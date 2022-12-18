from typing import Dict


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


if __name__ == '__main__':
    # setTests = SET_Tests();
    # setTests.create()
    # setTests.list_to_set()
    # setTests.difference()
    # setTests.union()
    # setTests.TESTS()

    # loops = Loops();
    # loops.loop1()

    '''
    log('Hi there!')
    sleep(0.1)
    log('Hello again!')'''

    tree = CategoryTree()
    tree.add("A", "B")
    tree.add("A", "C")
    tree.add("A", "D")

    tree.add("C", "F")
    tree.add("C", "G")

    tree.print()