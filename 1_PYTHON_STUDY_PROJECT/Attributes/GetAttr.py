class TestObject:

    def __init__(self, value):
        super().__init__()
        self.__val = value

    @property
    def value(self):
        return self.__val

    @value.setter
    def value(self, v):
        self.__val = v

    def get_value(self):
        return self.__val


def get_attribute():
    obj = TestObject("Test")

    print(obj.value, obj.get_value())

    val = getattr(obj, 'value')
    func = getattr(obj, 'get_value')

    print(val, func())


def get_attribute_update():
    obj = TestObject("Test")

    print(obj.value, obj.get_value())

    val = getattr(obj, 'value')
    func = getattr(obj, 'get_value')

    print(val, func())

    obj.value = "Test_NEW"

    print(f'\n{val}', func())
    val = getattr(obj, 'value')
    print(val, func())


class TestClass(object):
    def __getattr__(self, attribute_name: str):
        print(f'{self.__class__.__name__}::__getattr__() method called')
        if attribute_name == "value":
            return 40
        else:
            raise AttributeError(f"NOT EXISTING: {attribute_name}")


def getattr_test():
    T = TestClass()
    print(T.value)


def getattr_test_non_existing():
    T = TestClass()
    print(T.some_not_existing_attr)


if __name__ == "__main__":
    # get_attribute()
    # get_attribute_update()

    # getattr_test()
    getattr_test_non_existing()
