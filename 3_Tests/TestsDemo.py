class CategoryTree2:

    def __init__(self):
        self.data = {}

    def add_category(self, category, parent):
        if parent is None:
            if category in self.data:
                raise KeyError(category)
            else:
                self.data[category] = []
        else:
            if parent in self.data:
                self.data[parent].append(category)
            else:
                self.data[parent] = [category]

    def get_children(self, parent):
        return self.data[parent]


    def test(self):
        print(self.data)


class Node:
    def __init__(self, name) -> None:
        self.name = name
        self.data = []

    def __repr__(self):
        return f'{self.name}'


class CategoryTree:

    def __init__(self):
        self.root = None

    def add_category(self, category, parent):
        if parent is None:
            self.root = Node(category)
        else:
            # print(self.root[(Node(parent))])
            self.root.data.append(Node(category))

    def get_children(self, parent):
        return


    def test(self):
        print(self.data)


def is_sublist(list1, list2, start) -> bool:
    size1, size2 = len(list1), len(list2)
    for i in range(0, size1):
        if ((start + i) == size2) or (list1[i] != list2[i + start]):
            return False
    return True


if __name__ == "__main__":

    original = [1, 4, 3, 2]
    desired = [1, 2, 4, 3]


    result = 0
    size: int = len(desired)
    for n in range(0, size):
        maxlen = 0
        for i in range(n, size):
            piece = desired[n: i + 1]
            print("piece" ,piece)
            if is_sublist(piece, original, result):
                print("Match", piece, original)
                maxlen = i + 1 - n
            else:
                break
            result += maxlen


    print(result)


















