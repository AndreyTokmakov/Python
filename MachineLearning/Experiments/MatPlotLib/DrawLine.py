
import math
import matplotlib.pyplot as plt
import numpy as np

from functools import reduce
from typing import List

def DrawLine():
    a = 21
    b = 2

    x = [1, 2, 3, 4, 5]
    y = [(v * a + b) for v in x]

    plt.scatter(x, y)
    plt.show()

if __name__ == '__main__':
    DrawLine()