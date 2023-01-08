
class Singleton(object):

    def __new__(cls):
        if not hasattr(cls, 'instance'):
            cls.instance = super(Singleton, cls).__new__(cls)

        return cls.instance

    def __init__(self):
        print("Singleton created")
        self.__counter: int = 0

    @property
    def counter(self):
        return self.__counter

    @counter.setter
    def counter(self, a):
        self.__counter = a


if __name__ == '__main__':
    s1, s2 = Singleton(), Singleton()

    assert s1 == s2
    assert s1 is s2

    print(s1.counter)
    s1.counter = 12
    print(s2.counter)
