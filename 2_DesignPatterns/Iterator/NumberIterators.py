

class OddIterator(object):

    def __init__(self, container):
        self.container = container
        self.n = -1

    def __next__(self):
        self.n += 2
        if self.n > self.container.maximum:
            raise StopIteration
        return self.n

    def __iter__(self):
        return self


class OddNumbers(object):

    def __init__(self, maximum):
        self.maximum = maximum

    def __iter__(self):
        return OddIterator(self)


if __name__ == '__main__':
    numbers = OddNumbers(10)
    for n in numbers:
        print(n)

