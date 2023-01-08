class SingletonMeta(type):
    """
    The Singleton class can be implemented in different ways in Python. Some
    possible methods include: base class, decorator, metaclass. We will use the
    metaclass because it is best suited for this purpose.
    """

    _instances = {}

    def __call__(cls, *args, **kwargs):
        """
        Possible changes to the value of the `__init__` argument do not affect
        the returned instance.
        """
        if cls not in cls._instances:
            instance = super().__call__(*args, **kwargs)
            cls._instances[cls] = instance
        return cls._instances[cls]


class Singleton(metaclass=SingletonMeta):

    def __init__(self):
        print("Singleton created")
        self.__counter: int = 0

    def some_business_logic(self):
        """
        Finally, any singleton should define some business logic, which can be executed on its instance.
        """

    @property
    def counter(self):
        return self.__counter

    @counter.setter
    def counter(self, a):
        self.__counter = a


if __name__ == "__main__":
    s1, s2 = Singleton(), Singleton()

    assert s1 == s2
    assert s1 is s2

    print(s1.counter)
    s1.counter = 12
    print(s2.counter)
