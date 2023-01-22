from typing import List


class Singleton(object):
    __instance = None

    def __init__(self):
        if Singleton.__instance is not None:
            raise RuntimeError("Already created")
        else:
            Singleton.__instance = self

    @staticmethod
    def getInstance():
        if not Singleton.__instance:
            Singleton.__instance = Singleton()
        return Singleton.__instance


if __name__ == "__main__":
    s1 = Singleton.getInstance()
    s2 = Singleton.getInstance()

    assert s1 == s2
    assert s1 is s2

    s1.x = 1

    print(s2.x)
