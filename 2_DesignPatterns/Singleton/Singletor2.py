
class Singleton:
    instance = None

    def __new__(cls):
        if cls.instance is None:
            cls.instance = super().__new__(cls)

        return cls.instance

    def __init__(self):
        print("Created()")


if __name__ == '__main__':
   s1 = Singleton()
   s2 = Singleton()

   print(s1 == s2)
   print(s1 is s2)