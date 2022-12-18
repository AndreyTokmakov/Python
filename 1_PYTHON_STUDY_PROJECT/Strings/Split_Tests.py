import re
from typing import List


def Test_RegEx():
    str = '63 41    92  81            69  70'

    # split string by single space
    chunks = re.split(' +', str)

    print(chunks)


def Split():
    str = '63 41    92  81            69  70'
    parts = [p for p in str.split(' ') if len(p) > 1]
    print(parts)


def Split_And_Join():
    a = "this is a string"
    parts: List = a.split(" ")
    result = '-'.join(parts)

    print(result)


if __name__ == '__main__':
    # Test_RegEx();
    # Split();
    # Split_And_Join();

    print("1 2 3".split())
