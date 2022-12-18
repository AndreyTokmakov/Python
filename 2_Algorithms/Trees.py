# A class that represents an individual node in a Binary Tree
class Node:
    def __init__(self, key) -> None:
        self.left = None
        self.right = None
        self.data = key


class BinaryTree:

    def __init__(self) -> None:
        self.root = None

    @staticmethod
    def __insert(node, key):
        if node is None:
            return Node(key)
        else:
            if node.data == key:
                return node
            elif node.data < key:
                node.right = BinaryTree.__insert(node.right, key)
            else:
                node.left = BinaryTree.__insert(node.left, key)
        return node

    def insert(self, key):
        self.root = BinaryTree.__insert(self.root, key)

#########################################################################################

# A function to do inorder tree traversal
def printInorder(root):
    if root:
        printInorder(root.left)
        print(root.data),
        printInorder(root.right)


def printPostorder(root):
    if root:
        printPostorder(root.left)  # First recur on left child
        printPostorder(root.right)  # the recur on right child
        print(root.data),


# A function to do preorder tree traversal
def printPreorder(root):
    if root:
        print(root.data)  # First print the data of node
        printPreorder(root.left)  # Then recur on left child
        printPreorder(root.right)  # Finally recur on right child


def printBackwards(root):
    if root:
        printBackwards(root.right)
        print(root.data)
        printBackwards(root.left)


def TreeWalks():
    root = Node(5)
    root.left = Node(3)
    root.right = Node(7)
    root.left.left = Node(1)
    root.left.right = Node(4)

    print("Preorder traversal of binary tree is")
    printPreorder(root)

    print("\nInorder traversal of binary tree is")
    printInorder(root)

    print("\nPostorder traversal of binary tree is")
    printPostorder(root)

    print("\nBackwards traversal of binary tree is")
    printBackwards(root)


# ---------------------------------------- Knapsack ---------------------------------------------------

def printLevelOrder(root):
    # Base Case
    if root is None:
        return

    queue = [root]  # Create an empty queue for level order traversal
    while len(queue) > 0:
        # Print front of queue and remove it from queue
        print(queue[0].data)
        node = queue.pop(0)

        # Enqueue left child
        if node.left is not None:
            queue.append(node.left)

        # Enqueue right child
        if node.right is not None:
            queue.append(node.right)


def LevelOrder():
    root = Node(5)
    root.left = Node(3)
    root.right = Node(7)
    root.left.left = Node(1)
    root.left.right = Node(4)

    printLevelOrder(root)




if __name__ == '__main__':
    # TreeWalks()
    LevelOrder()
