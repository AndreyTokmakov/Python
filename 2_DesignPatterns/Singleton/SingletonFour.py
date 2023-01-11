from typing import List


class Singleton:
    __instance = None
    __constructed: bool = False

    '''
    def __init__(self):
        if not Singleton.__instance:
            print(" __init__ method called..")
        else:
            print("Instance already created:", self.getInstance())
            
    @classmethod
    def getInstance(cls):
        if not cls.__instance:
            cls.__instance = Singleton()
        return cls.__instance
    '''

    def __init__(self):
        if not self.__constructed:
            self.__constructed = True
            return

        print(f"{self.__class__.__name__} constructor()")

        self.value: int = 0
        self.attributes: List = []

    def __new__(cls):
        if cls.__instance is None:
            cls.__instance = super().__new__(cls)

        return cls.__instance


if __name__ == "__main__":
    s1 = Singleton()
    s2 = Singleton()

    assert s1 == s2
    assert s1 is s2

    print(s1.value, s2.value)

    s1.value = 2

    print(s1.value, s2.value)

    assert s1.attributes == s2.attributes
    assert s1.attributes is s2.attributes