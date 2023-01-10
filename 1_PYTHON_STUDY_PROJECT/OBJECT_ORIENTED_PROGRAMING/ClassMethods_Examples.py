class TestClassOne(object):
    __class_description__: str = "TestClassOne"

    def __init__(self):
        self.value: int = 123

    @staticmethod
    def method_static():
        print("\nstatic method")
        # print(self.value)  # Not allowed
        pass

    @classmethod
    def method_class(cls):
        print("\nclass method")
        # print(self.value)  # Not allowed
        print('\t', cls.__class_description__)  # OK
        pass

    def method_instance(self):
        print("\ninstance method")
        print('\t', self.value)  # Not allowed
        print('\t', self.__class_description__)  # OK
        pass


if __name__ == '__main__':
    o1 = TestClassOne()
    o1.method_static()
    o1.method_class()
    o1.method_instance()
