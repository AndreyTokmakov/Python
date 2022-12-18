
class TestObject:

    def __init__(self, value):
        self.__val = value
        super().__init__()
    
    @property
    def value(self):
        return self.__val;
    
    
    def getValue(self):
        return self.__val;

if __name__ == "__main__":
    obj = TestObject("Test")
    
    print(obj.value)
    print(obj.getValue())
    
    func = getattr(obj, 'getValue')
    print(func());
    
    val = getattr(obj, 'value')
    print(val);
    
    
    obj2 = TestObject("Test2")
    print(obj2.value)
    
    val2 = getattr(obj2, 'value')
    print(val2);
    print(obj2.value)
    
    val2 = "123";
    
    print(val2);
    print(obj2.value)