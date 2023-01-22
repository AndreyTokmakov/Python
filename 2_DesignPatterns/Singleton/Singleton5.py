from __future__ import annotations


class Singleton:
    __instance: Singleton = None
    # __constructed: bool = False

    '''
    def __init__(self):
        if not self.__constructed:
            print(f"{self.__class__.__name__} constructor()")
            self.value: int = 0
            self.attributes: List = []
            self.__constructed = True
    '''

    def __init__(self):
        print(f'{self.__class__.__name__} constructor called')
        self.some_list = []

    def __new__(cls):
        if cls.__instance is None:
            cls.__instance = super(Singleton, cls).__new__(cls)
        return cls.__instance


if __name__ == "__main__":
    s1 = Singleton()

    s1.some_list.append(1)
    s1.some_list.append(2)

    s2 = Singleton()

    s2.some_list.append(3)

    assert s1 == s2
    assert s1 is s2


    print(s2.some_list)

    '''
    print(s1.value, s2.value)

    s1.value = 2

    print(s1.value, s2.value)

    assert s1.attributes == s2.attributes
    assert s1.attributes is s2.attributes
    '''
