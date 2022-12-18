
class MyObject(object):
    def __init__(self):
        # super().__init__()
        self.__value = 0

    @property
    def value(self):
        return self.__value

    @value.setter
    def value(self, value):
        self.__value = value

    def __repr__(self):
        return f'MyObject({self.__value})'

    def __str__(self):
        return f'MyObject({self.__value})'


if __name__ == '__main__':
    obj = MyObject()

    obj.value = 123

    print(obj)
